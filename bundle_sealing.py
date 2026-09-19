"""Final bundle sealing, bootstrap verifier publication, and signatures."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional, Protocol

from openpgp_verifier import gpg_backend_version
from repository_paths import human_size

SEAL_PHASE_START = 0.8
INDEX_FILENAME = "bundle-index.json"
INDEX_SIGNATURE = "bundle-index.json.asc"


class SealReporter(Protocol):
    def check_cancel(self) -> None: ...
    def progress(self, message: str, fraction: float) -> None: ...
    def warn(self, message: str, /) -> None: ...
    def log(self, message: str, /) -> None: ...


def verify_script(base_file: Optional[Path] = None) -> str:
    """Load the receiver-side verifier and fail closed if packaging omitted it."""
    source_file = Path(__file__) if base_file is None else Path(base_file)
    candidates = [source_file.resolve().parent / "verify_bundle_template.py"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.insert(0, Path(meipass) / "verify_bundle_template.py")
    last_error: Optional[OSError] = None
    for template in candidates:
        try:
            body = template.read_text(encoding="utf-8")
        except OSError as exc:
            last_error = exc
            continue
        if body.strip():
            return body
    detail = f" ({last_error})" if last_error else ""
    raise RuntimeError(
        "Receiver verifier resource verify_bundle_template.py is missing or empty. "
        "Refusing to seal a bundle without verify-bundle.py" + detail
    )


def make_executable(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        pass


def sign_detached(path: Path, signing_key: str, reporter: SealReporter) -> Optional[Path]:
    """Create an armoured detached signature, or return None when unavailable."""
    if shutil.which("gpg") is None:
        reporter.warn(f"gpg is not installed, so {path.name} could not be signed.")
        return None
    signature = path.with_suffix(path.suffix + ".asc")
    proc = subprocess.run(
        [
            "gpg",
            "--batch",
            "--yes",
            "--armor",
            "--local-user",
            signing_key,
            "--detach-sign",
            "--output",
            str(signature),
            str(path),
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip().splitlines()
        reporter.warn(
            f"Signing {path.name} failed: "
            + (detail[-1] if detail else "unknown error")
        )
        return None
    reporter.log(f"Signed {path.name}: {signature.name}")
    return signature


def write_bundle_index(
    bundle_dir: Path,
    reporter: SealReporter,
    metadata: Dict[str, object],
    signing_key: str = "",
    *,
    verify_script_fn: Callable[[], str] = verify_script,
    make_executable_fn: Callable[[Path], None] = make_executable,
    sign_detached_fn: Callable[[Path, str, SealReporter], Optional[Path]] = sign_detached,
    gpg_version_fn: Callable[[], str] = gpg_backend_version,
    default_tool: str = "Feathered",
) -> Path:
    """Hash every finished file and record them in one canonical index."""
    bundle_dir = Path(bundle_dir)
    body = verify_script_fn()
    verifier = bundle_dir / "verify-bundle.py"
    verifier.write_text(body, encoding="utf-8", newline="\n")
    make_executable_fn(verifier)
    if signing_key:
        verifier_signature = sign_detached_fn(verifier, signing_key, reporter)
        if verifier_signature is None:
            raise RuntimeError(
                "Bundle signing was requested but verify-bundle.py could not be signed. "
                "The bundle has not been published."
            )

    excluded = {INDEX_FILENAME, INDEX_SIGNATURE}
    files = []
    for candidate in bundle_dir.rglob("*"):
        relative = candidate.relative_to(bundle_dir).as_posix()
        if relative in excluded:
            continue
        if candidate.is_symlink():
            raise RuntimeError(
                f"Refusing to seal a bundle containing a symlink ({relative}); its target may "
                "lie outside the bundle and would not be covered by the signature."
            )
        if candidate.is_file():
            files.append(candidate)
    files.sort(key=lambda path: path.relative_to(bundle_dir).as_posix())
    total = sum(path.stat().st_size for path in files) or 1
    done = 0
    entries = []
    for path in files:
        reporter.check_cancel()
        digest = hashlib.sha256()
        hashed = 0
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(4 * 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                hashed += len(chunk)
                done += len(chunk)
                reporter.progress(
                    f"Sealing bundle ({human_size(done)} of {human_size(total)})",
                    done / total,
                )
        if path.stat().st_size != hashed:
            raise RuntimeError(
                f"{path.name} changed while the bundle was being sealed; "
                "rebuild rather than publishing an index that does not match."
            )
        entries.append(
            {
                "path": path.relative_to(bundle_dir).as_posix(),
                "sha256": digest.hexdigest(),
                "size": str(hashed),
            }
        )
    total_bytes = sum(int(entry["size"]) for entry in entries)
    index: Dict[str, object] = {
        "format": "feathered-bundle-index/1",
        "tool": metadata.get("tool", default_tool),
        "bundle_id": str(metadata.get("bundle_id") or bundle_dir.name),
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": metadata.get("target", {}),
        "trust": metadata.get("trust", {}),
        "openpgp_verifier": gpg_version_fn() or "unavailable",
        "file_count": len(entries),
        "total_bytes": total_bytes,
        "files": entries,
    }
    payload = json.dumps(
        index,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    target = bundle_dir / INDEX_FILENAME
    target.write_bytes(payload)
    if signing_key:
        signature = sign_detached_fn(target, signing_key, reporter)
        if signature is None:
            raise RuntimeError(
                "Bundle signing was requested but no signature could be produced. The bundle has "
                "not been published; fix the signing key or disable signing and rebuild."
            )
    return target
