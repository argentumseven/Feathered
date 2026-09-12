"""Write deterministic integrity metadata for a staged Feathered distribution."""
from __future__ import annotations

import hashlib
import json
import platform
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from core import FEATHERED_VERSION

ROOT = Path(__file__).resolve().parent
DIST = ROOT / "dist"
MANIFEST = DIST / "RELEASE-MANIFEST.json"
SUMS = DIST / "SHA256SUMS.txt"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def command_version(args: list[str]) -> str:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    lines = (proc.stdout or proc.stderr or "").strip().splitlines()
    return lines[0].strip() if proc.returncode == 0 and lines else ""


def git_commit() -> str:
    try:
        proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def main() -> None:
    if not DIST.is_dir() or not (DIST / "Feathered.exe").is_file():
        raise SystemExit("dist/Feathered.exe is missing; build the release before writing its manifest")

    excluded = {MANIFEST.resolve(), SUMS.resolve()}
    files = []
    for path in sorted((p for p in DIST.rglob("*") if p.is_file()),
                       key=lambda p: p.relative_to(DIST).as_posix().lower()):
        if path.resolve() in excluded:
            continue
        files.append({
            "path": path.relative_to(DIST).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        })

    requirements = ROOT / "requirements.txt"
    build_mode = os.environ.get("FEATHERED_BUILD_MODE", "unknown").strip() or "unknown"
    build_lock_name = os.environ.get("FEATHERED_BUILD_LOCK", "").strip()
    if build_lock_name and (Path(build_lock_name).name != build_lock_name or build_lock_name in {".", ".."}):
        raise SystemExit("FEATHERED_BUILD_LOCK must name a file in the source root")
    build_requirements = ROOT / build_lock_name if build_lock_name else None
    manifest = {
        "schema": 1,
        "trust_model": "audit metadata only; executable-embedded verifier policy is the runtime trust root",
        "feathered_version": FEATHERED_VERSION,
        "generated_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_commit": git_commit(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "build_mode": build_mode,
        "build_requirements_lock": build_lock_name,
        "pip": command_version([sys.executable, "-m", "pip", "--version"]),
        "pyinstaller": command_version([sys.executable, "-m", "PyInstaller", "--version"]),
        "requirements_sha256": sha256(requirements) if requirements.is_file() else "",
        "build_requirements_lock_sha256": (
            sha256(build_requirements) if build_requirements is not None and build_requirements.is_file() else ""),
        "files": files,
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    sum_rows = [f'{entry["sha256"]}  {entry["path"]}' for entry in files]
    sum_rows.append(f"{sha256(MANIFEST)}  {MANIFEST.name}")
    SUMS.write_text("\n".join(sum_rows) + "\n", encoding="utf-8")
    print(f"Wrote {MANIFEST}")
    print(f"Wrote {SUMS}")


if __name__ == "__main__":
    main()
