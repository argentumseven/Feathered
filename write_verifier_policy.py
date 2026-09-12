"""Generate the exact-set SHA-256 policy embedded in Feathered.exe."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
GPG_DIR = ROOT / "dist" / "gnupg"
OUT = ROOT / "verifier-integrity.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if not (GPG_DIR / "gpgv.exe").is_file():
        raise SystemExit("dist/gnupg/gpgv.exe is missing")
    files = {}
    for path in sorted(GPG_DIR.rglob("*"), key=lambda p: p.relative_to(GPG_DIR).as_posix().lower()):
        if path.is_symlink():
            raise SystemExit(f"refusing symlink/reparse entry in verifier staging: {path}")
        if path.is_file():
            files[path.relative_to(GPG_DIR).as_posix()] = sha256(path)
    if "gpgv.exe" not in files:
        raise SystemExit("gpgv.exe was not included in verifier policy")
    OUT.write_text(json.dumps({"schema": 1, "files": files}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} for {len(files)} verifier files")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
