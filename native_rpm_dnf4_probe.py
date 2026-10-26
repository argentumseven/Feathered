"""Record DNF4's proposed RPM transactions on disposable EL10 installroots.

DNF4 does not support DNF5's transaction ``--store``. Instead ``--assumeno``
lets the native solver produce a plan and refuses its application. The JSON
distinguishes a proposed transaction from an RPM transaction that ran; it
does not certify installed-host compatibility or package download success.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from native_rpm_live_probe import select_roots
from workloads import load_workloads


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)


def classify_dnf4(exit_code: int, output: str) -> str:
    """An abort *after* a transaction summary is an accepted solve, not a failure."""
    if "Transaction Summary" in output:
        return "dnf-proposed-no-install"
    if exit_code != 0:
        return "dnf-no-transaction"
    return "dnf-indeterminate"


def probe(profile: str, release: str, presets: list[str], output: Path) -> dict:
    if profile not in {"centos-stream", "rocky", "alma"}:
        raise ValueError("The DNF4 diagnostic is scoped to the three EL10 profiles")
    output.mkdir(parents=True, exist_ok=True)
    # CRB is enabled by the Feathered EL10 templates. Include it even when the
    # native container disables it by default, so source sets are comparable.
    base = ["dnf", f"--releasever={release}", "--enablerepo=crb"]
    query = _run([*base, "repoquery", "--available", "--qf=%{name}"])
    (output / "repoquery.log").write_text(query.stdout + query.stderr, encoding="utf-8")
    if query.returncode:
        raise RuntimeError(f"DNF4 repoquery failed with exit {query.returncode}; see repoquery.log")
    available = set(query.stdout.splitlines())
    if len(available) < 100:
        raise RuntimeError(f"DNF4 repoquery listed only {len(available)} names; refusing an empty diagnostic")
    catalog = load_workloads()
    results: dict = {}
    for key in presets:
        if key not in catalog:
            raise ValueError(f"Unknown workload preset: {key}")
        roots, missing, skipped = select_roots(catalog[key].source_plan("rpm"), available)
        data: dict[str, object] = {"requested_roots": roots,
                                   "missing_required_roots": missing,
                                   "skipped_optional_roots": skipped}
        if missing:
            data["status"] = "missing-required-roots"
        elif not roots:
            data["status"] = "no-selected-roots"
        else:
            with tempfile.TemporaryDirectory(prefix="feathered-dnf4-") as target:
                command = [*base, f"--installroot={target}",
                           "--setopt=reposdir=/etc/yum.repos.d", "--assumeno",
                           "install", *roots]
                result = _run(command)
            output_text = result.stdout + result.stderr
            (output / f"{key}.log").write_text(output_text, encoding="utf-8")
            data["status"] = classify_dnf4(result.returncode, output_text)
            data["exit_code"] = result.returncode
            data["log"] = f"{key}.log"
        results[key] = data
    report = {"profile": profile, "releasever": release,
              "validation_scope": "DNF4 native solver on empty RPMDB with --assumeno; no target packages installed",
              "presets": results}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                         encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--releasever", default="10")
    parser.add_argument("--presets", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    report = probe(args.profile, args.releasever, args.presets.split(","), args.out)
    for key, row in report["presets"].items():
        print(f"{key}: {row['status']} ({len(row['requested_roots'])} roots)")
    return 0  # Completing diagnostic collection does not assert compatibility.


if __name__ == "__main__":
    raise SystemExit(main())
