"""Capture native DNF5 and optional RPM --test decisions, without install.

This is a diagnostic comparison oracle, not a release gate. A successful
probe means DNF accepted the requested roots for an *empty* target RPMDB;
it does not validate Feathered's selected package set or an existing host.
With --rpm-test, the stored DNF transaction is also checked by RPM in a
disposable empty root; neither mode installs target packages.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from workloads import load_workloads


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, timeout=600)


def select_roots(plan, available: set[str]) -> tuple[list[str], list[str], list[str]]:
    """Apply the catalog's ordered candidates/optionality to native names."""
    roots: list[str] = []
    missing: list[str] = []
    skipped: list[str] = []
    for root in plan.roots:
        if root.source_kind != "distribution":
            raise ValueError(f"{root.package}: probe cannot silently omit vendor repository")
        candidate = next((name for name in (root.candidates or (root.package,))
                          if name in available), None)
        if candidate:
            roots.append(candidate)
        elif root.optional:
            skipped.append(root.package)
        else:
            missing.append(root.package)
    return roots, missing, skipped


def probe(profile: str, release: str, presets: list[str], output: Path,
          *, rpm_test: bool = False) -> dict:
    if profile != "fedora":
        raise ValueError("Only Fedora DNF5 repository configuration is currently verified")
    output.mkdir(parents=True, exist_ok=True)
    # DNF5 does not append a newline per queryformat record by default.
    # Without an explicit separator, every name becomes one long fake name.
    query = _run(["dnf5", "--refresh", "repoquery", "--available",
                  "--queryformat=%{name}\\n"])
    (output / "repoquery.log").write_text(query.stdout + query.stderr, encoding="utf-8")
    if query.returncode:
        raise RuntimeError(f"DNF5 repoquery failed with exit {query.returncode}; see repoquery.log")
    available = set(query.stdout.splitlines())
    if len(available) < 100:
        raise RuntimeError(f"DNF5 repoquery listed only {len(available)} names; refusing an empty diagnostic")
    catalog = load_workloads()
    results: dict = {}
    for key in presets:
        if key not in catalog:
            raise ValueError(f"Unknown workload preset {key}")
        plan = catalog[key].source_plan("rpm")
        roots, missing, skipped = select_roots(plan, available)
        data: dict[str, object] = {"requested_roots": roots, "missing_required_roots": missing,
                                   "skipped_optional_roots": skipped}
        if missing:
            data["status"] = "missing-required-roots"
        elif not roots:
            data["status"] = "no-selected-roots"
        else:
            # Fresh root prevents the Fedora container's preinstalled packages
            # from masking dependencies. DNF uses the host's public repo files.
            with tempfile.TemporaryDirectory(prefix="feathered-dnf5-") as root:
                stored = output / f"{key}-transaction"
                result = _run([
                    # --store guarantees no installation, but DNF still asks
                    # confirmation before writing the transaction plan.
                    "dnf5", "-y", f"--installroot={root}", f"--releasever={release}",
                    "--setopt=reposdir=/etc/yum.repos.d", "install",
                    f"--store={stored.resolve()}", *roots,
                ])
                if result.returncode == 0 and rpm_test:
                    # DNF's accepted plan is a solver observation. Check its
                    # *actual stored RPM set* with RPM's dependency validator,
                    # still against an empty disposable root and without any
                    # installation or dependency bypass.
                    package_files = sorted((stored / "packages").glob("*.rpm"))
                    if not package_files:
                        raise RuntimeError(
                            f"DNF5 accepted {key} but stored no RPMs for a transaction check")
                    checked = _run([
                        "rpm", "--root", root, "-U", "--test", "--nosignature",
                        *(str(path.resolve()) for path in package_files),
                    ])
                    (output / f"{key}-rpm-test.log").write_text(
                        checked.stdout + checked.stderr, encoding="utf-8")
                    data["rpm_test_status"] = (
                        "rpm-test-accepted" if checked.returncode == 0 else "rpm-test-rejected")
                    data["rpm_test_exit_code"] = checked.returncode
                    data["rpm_test_log"] = f"{key}-rpm-test.log"
            (output / f"{key}.log").write_text(result.stdout + result.stderr,
                                                   encoding="utf-8")
            data["status"] = "dnf-accepted" if result.returncode == 0 else "dnf-rejected"
            data["exit_code"] = result.returncode
            data["log"] = f"{key}.log"
        results[key] = data
    report = {"profile": profile, "release": release,
              "validation_scope": (
                  "DNF5 native solver and RPM --test of stored RPMs in disposable empty roots; "
                  "no packages installed" if rpm_test else
                  "DNF5 native solver on empty RPMDB, stored transaction only; no packages installed"),
              "presets": results}
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                         encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", default="fedora")
    parser.add_argument("--release", required=True)
    parser.add_argument("--presets", default="cockpit,kernel-dev,storage-tools")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--rpm-test", action="store_true",
                        help="Also test the stored RPM transaction in a disposable empty root")
    args = parser.parse_args()
    report = probe(args.profile, args.release, args.presets.split(","), args.out,
                   rpm_test=args.rpm_test)
    for key, row in report["presets"].items():
        native_note = f", {row['rpm_test_status']}" if 'rpm_test_status' in row else ''
        print(f"{key}: {row['status']}{native_note} ({len(row['requested_roots'])} roots)")
    return 0  # Diagnostic completion is not a compatibility assertion.


if __name__ == "__main__":
    raise SystemExit(main())
