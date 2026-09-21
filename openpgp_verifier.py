"""OpenPGP verifier discovery, integrity authentication, and signature checks.

The bundled verifier is part of Feathered's trust boundary.  This module owns
its exact-set integrity policy and keyring preparation.  Callers may inject a
small number of lookup hooks so the legacy ``core`` façade remains monkeypatch
compatible while new code can use this module directly.
"""
from __future__ import annotations
import base64
import binascii
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Callable, Dict, Optional, Protocol, Union

import file_hashing
import hashlib


class VerifierReporter(Protocol):
    def log(self, message: str, /) -> None: ...


class VerifierIntegrityError(RuntimeError):
    """The bundled OpenPGP verifier is missing, unauthenticated, or tampered."""

def bundled_gpg_dir() -> Optional[Path]:
    try:
        roots = []
        if getattr(sys, "frozen", False):
            roots.append(Path(sys.executable).resolve().parent)
        roots.append(Path(__file__).resolve().parent)
        for root in roots:
            candidate = root / "gnupg"
            if candidate.is_dir():
                return candidate
    except OSError:
        pass
    return None

def verifier_policy_path() -> Optional[Path]:
    roots = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass))
    roots.append(Path(__file__).resolve().parent)
    for root in roots:
        candidate = root / "verifier-integrity.json"
        if candidate.is_file():
            return candidate
    return None


def sha256_file(path: Path) -> str:
    return file_hashing.stream_digest(path, hashlib.sha256())

_VERIFIER_CACHE_LOCK = threading.Lock()
_VERIFIER_VERIFIED: Dict[str, frozenset[tuple[str, int, int]]] = {}


def verifier_fingerprint(files: Dict[str, Path]) -> frozenset[tuple[str, int, int]]:
    return frozenset(
        (rel, path.stat().st_size, path.stat().st_mtime_ns)
        for rel, path in files.items()
    )

def enumerate_verifier_files(directory: Path) -> Dict[str, Path]:
    found: Dict[str, Path] = {}
    try:
        for path in directory.rglob("*"):
            if path.is_symlink():
                raise VerifierIntegrityError(
                    f"Bundled OpenPGP verifier contains a symlink/reparse entry: {path.name}"
                )
            if path.is_file():
                found[path.relative_to(directory).as_posix()] = path
    except OSError as exc:
        raise VerifierIntegrityError(
            "Unable to enumerate bundled OpenPGP verifier files."
        ) from exc
    return found

def verify_bundled_gpg_integrity(
    directory: Path,
    *,
    policy_path_fn: Callable[[], Optional[Path]] = verifier_policy_path,
    sha256_file_fn: Callable[[Path], str] = sha256_file,
) -> None:
    policy_path = policy_path_fn()
    frozen = bool(getattr(sys, "frozen", False))
    if policy_path is None:
        if frozen:
            raise VerifierIntegrityError(
                "Bundled OpenPGP verifier integrity policy is missing from this release. "
                "Refusing to execute an unauthenticated verifier."
            )
        return
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        expected = policy["files"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier integrity policy is invalid."
        ) from exc
    if not isinstance(expected, dict) or not expected:
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier integrity policy contains no files."
        )
    actual = enumerate_verifier_files(directory)
    expected_names = set(expected)
    actual_names = set(actual)
    if actual_names != expected_names:
        missing = sorted(expected_names - actual_names)
        extra = sorted(actual_names - expected_names)
        detail = []
        if missing:
            detail.append("missing: " + ", ".join(missing))
        if extra:
            detail.append("unexpected: " + ", ".join(extra))
        raise VerifierIntegrityError(
            "Bundled OpenPGP verifier file set does not match the signed release policy"
            + (" (" + "; ".join(detail) + ")" if detail else "")
            + "."
        )
    key = str(directory.resolve())
    try:
        fingerprint = verifier_fingerprint(actual)
    except OSError as exc:
        raise VerifierIntegrityError(
            "Unable to stat bundled OpenPGP verifier files."
        ) from exc

    with _VERIFIER_CACHE_LOCK:
        cached = _VERIFIER_VERIFIED.get(key) == fingerprint
    def check(rel: str, path: Path) -> None:
        wanted = str(expected[rel]).lower()
        if len(wanted) != 64 or any(c not in "0123456789abcdef" for c in wanted):
            raise VerifierIntegrityError(
                f"Invalid verifier SHA-256 policy entry for {rel}."
            )
        if sha256_file_fn(path).lower() != wanted:
            raise VerifierIntegrityError(
                f"Bundled OpenPGP verifier integrity check failed for {rel}. "
                "Refusing to execute it."
            )
    if cached:
        # Size and mtime are useful cache metadata, but they are not a trust
        # boundary: an attacker with write access can replace a sidecar and
        # restore both values.  Re-hash the complete authenticated file set even
        # when its metadata fingerprint matches a prior verification.
        for rel, path in actual.items():
            check(rel, path)
        return

    for rel, path in actual.items():
        check(rel, path)

    with _VERIFIER_CACHE_LOCK:
        _VERIFIER_VERIFIED[key] = fingerprint


def reset_verifier_integrity_cache() -> None:
    with _VERIFIER_CACHE_LOCK:
        _VERIFIER_VERIFIED.clear()

def gpg_backend_name(backend: Optional[str]) -> str:
    if not backend:
        return ""
    stem = Path(backend).name.lower()
    return stem[:-4] if stem.endswith(".exe") else stem


def windows_path_to_msys(value: str) -> str:
    normalized = value.replace("\\", "/")
    match = re.match(r"^([A-Za-z]):/(.*)$", normalized)
    if match:
        return f"/{match.group(1).lower()}/{match.group(2)}"
    return normalized

def gpg_backend_uses_msys_paths(backend: str) -> bool:
    if os.name != "nt":
        return False
    resolved = shutil.which(backend) or backend
    normalized = str(resolved).replace("\\", "/").lower()
    if "/git/usr/bin/" in normalized:
        return True
    try:
        return (Path(resolved).resolve().parent / "msys-2.0.dll").is_file()
    except OSError:
        return False

def gpg_path_arg(
    path: Union[Path, str],
    backend: str,
    *,
    uses_msys_fn: Callable[[str], bool] = gpg_backend_uses_msys_paths,
) -> str:
    value = str(path)
    return windows_path_to_msys(value) if uses_msys_fn(backend) else value

def gpg_backend(
    *,
    bundled_dir_fn: Callable[[], Optional[Path]] = bundled_gpg_dir,
    verify_integrity_fn: Callable[[Path], None] = verify_bundled_gpg_integrity,
) -> Optional[str]:
    bundled = bundled_dir_fn()
    frozen = bool(getattr(sys, "frozen", False))
    if bundled is not None:
        verify_integrity_fn(bundled)
        for candidate in ("gpgv.exe", "gpgv"):
            tool = bundled / candidate
            if tool.is_file():
                return str(tool)
        if frozen:
            raise VerifierIntegrityError(
                "Authenticated OpenPGP verifier directory contains no gpgv executable."
            )
    elif frozen:
        raise VerifierIntegrityError(
            "This Feathered release is missing its bundled OpenPGP verifier. "
            "Refusing to fall back to an unauthenticated PATH executable."
        )
    # Verification deliberately requires gpgv.  Ordinary gpg reads user
    # configuration and can consult keyboxd/automatic-key-retrieval state,
    # which breaks the semantic guarantee that verification is confined to the
    # operator-configured repository keyring.
    return "gpgv" if shutil.which("gpgv") else None

def gpg_backend_or_none(
    *,
    backend_fn: Callable[[], Optional[str]] = gpg_backend,
) -> Optional[str]:
    try:
        return backend_fn()
    except VerifierIntegrityError:
        return None

def gpg_backend_version(
    backend: Optional[str] = None,
    *,
    backend_or_none_fn: Callable[[], Optional[str]] = gpg_backend_or_none,
) -> str:
    tool = backend or backend_or_none_fn()
    if not tool:
        return ""
    try:
        proc = subprocess.run(
            [tool, "--version"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    first = (proc.stdout or "").strip().splitlines()
    return first[0].strip() if proc.returncode == 0 and first else ""

MAX_ARMORED_KEYRING_BYTES = 32 * 1024 * 1024

def dearmor_public_keyring(data: bytes) -> bytes:
    begin = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    end = b"-----END PGP PUBLIC KEY BLOCK-----"
    lines = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == begin)
    except StopIteration as exc:
        raise RuntimeError(
            "ASCII keyring is missing an OpenPGP public-key armour header"
        ) from exc
    body_started = False
    body = []
    armor_crc: Optional[bytes] = None
    saw_end = False
    for raw in lines[start + 1 :]:
        line = raw.strip()
        if not body_started:
            if not line:
                body_started = True
                continue
            if b":" in line:
                continue
            body_started = True
        if line == end:
            saw_end = True
            break
        if not line:
            continue
        if line.startswith(b"="):
            if armor_crc is not None:
                raise RuntimeError("ASCII keyring contains multiple armour checksums")
            armor_crc = line[1:]
            continue
        body.append(line)
    if not saw_end:
        raise RuntimeError("ASCII keyring is missing its OpenPGP armour footer")
    if not body:
        raise RuntimeError("ASCII keyring contains no OpenPGP public-key data")
    try:
        decoded = base64.b64decode(b"".join(body), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("ASCII keyring contains invalid base64 armour data") from exc
    if not decoded:
        raise RuntimeError("ASCII keyring decoded to an empty OpenPGP keyring")
    if armor_crc is not None:
        try:
            expected_crc = base64.b64decode(armor_crc, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise RuntimeError("ASCII keyring contains an invalid armour checksum") from exc
        if len(expected_crc) != 3:
            raise RuntimeError("ASCII keyring contains an invalid armour checksum")
        crc = 0xB704CE
        for octet in decoded:
            crc ^= octet << 16
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= 0x1864CFB
        actual_crc = (crc & 0xFFFFFF).to_bytes(3, "big")
        if not hmac.compare_digest(actual_crc, expected_crc):
            raise RuntimeError("ASCII keyring armour checksum does not match its contents")
    return decoded

def prepare_keyring(keyring_path: Path, tmpdir: Path, backend: str) -> Path:
    try:
        with keyring_path.open("rb") as handle:
            head = handle.read(64)
            if not head.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK"):
                return keyring_path
            handle.seek(0)
            data = handle.read(MAX_ARMORED_KEYRING_BYTES + 1)
    except OSError as exc:
        raise RuntimeError(
            f"Could not read configured keyring {keyring_path}: {exc}"
        ) from exc
    if len(data) > MAX_ARMORED_KEYRING_BYTES:
        raise RuntimeError(
            f"ASCII keyring {keyring_path.name} exceeds Feathered's "
            f"{MAX_ARMORED_KEYRING_BYTES:,}-byte safety limit"
        )
    target = tmpdir / "keyring.gpg"
    target.write_bytes(dearmor_public_keyring(data))
    return target

def verify_openpgp(
    signed_payload: bytes,
    signature: Optional[bytes],
    keyring: str,
    description: str,
    reporter: VerifierReporter,
    *,
    backend_fn: Callable[[], Optional[str]] = gpg_backend,
    prepare_keyring_fn: Callable[[Path, Path, str], Path] = prepare_keyring,
    backend_name_fn: Callable[[Optional[str]], str] = gpg_backend_name,
    path_arg_fn: Callable[[Union[Path, str], str], str] = gpg_path_arg,
) -> None:
    keyring_path = Path(keyring).expanduser()
    if not keyring_path.is_file():
        raise RuntimeError(
            f"{description}: configured keyring was not found: {keyring_path}"
        )
    backend = backend_fn()
    if backend is None:
        raise RuntimeError(
            f"{description}: a keyring is configured but gpgv is not installed. "
            "Install the GnuPG verifier (gpgv; Gpg4win on Windows) or clear the keyring "
            "setting for this repository. Feathered does not fall back to ordinary gpg for verification."
        )
    if backend_name_fn(backend) != "gpgv":
        raise RuntimeError(
            f"{description}: OpenPGP verification requires gpgv; refusing verifier "
            f"{Path(backend).name!r} because it may consult user configuration or external key stores."
        )
    with tempfile.TemporaryDirectory(prefix="feathered-gpg-") as tmpdir:
        tmp = Path(tmpdir)
        keyring_arg = prepare_keyring_fn(keyring_path, tmp, backend)
        payload_file = tmp / "payload"
        payload_file.write_bytes(signed_payload)
        if signature is None:
            args = [path_arg_fn(payload_file, backend)]
        else:
            sig_file = tmp / "payload.sig"
            sig_file.write_bytes(signature)
            args = [path_arg_fn(sig_file, backend), path_arg_fn(payload_file, backend)]
        keyring_cli = path_arg_fn(keyring_arg, backend)
        cmd = [backend, "--keyring", keyring_cli, *args]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = [
                line
                for line in (proc.stderr or proc.stdout or "").strip().splitlines()
                if line.strip()
            ]
            raise RuntimeError(
                f"{description}: OpenPGP signature verification FAILED. "
                + (detail[-1] if detail else "no detail from the verifier")
            )
        signer = ""
        for line in (proc.stderr or "").splitlines():
            if "Good signature from" in line:
                signer = line.split("Good signature from", 1)[1].strip().strip('"')
                break
    reporter.log(
        f"{description}: OpenPGP signature verified"
        + (f" ({signer})" if signer else f" against {keyring_path.name}")
    )
