from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import openpgp_verifier
import package_acquisition
from execution_reporter import Reporter


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cached_verifier_integrity_rehashes_all_sidecars(tmp_path: Path) -> None:
    """Metadata-stable sidecar replacement must not bypass integrity checking."""
    verifier_dir = tmp_path / "gnupg"
    verifier_dir.mkdir()
    executable = verifier_dir / "gpgv.exe"
    sidecar = verifier_dir / "libexample.dll"
    executable.write_bytes(b"G" * 64)
    sidecar.write_bytes(b"A" * 64)

    policy_path = tmp_path / "verifier-integrity.json"
    policy_path.write_text(
        json.dumps(
            {
                "files": {
                    "gpgv.exe": _sha256(executable),
                    "libexample.dll": _sha256(sidecar),
                }
            }
        ),
        encoding="utf-8",
    )

    openpgp_verifier.reset_verifier_integrity_cache()
    try:
        openpgp_verifier.verify_bundled_gpg_integrity(
            verifier_dir,
            policy_path_fn=lambda: policy_path,
        )
        original_fingerprint = openpgp_verifier.verifier_fingerprint(
            openpgp_verifier.enumerate_verifier_files(verifier_dir)
        )
        stat_before = sidecar.stat()

        # Replace the sidecar with different bytes of the same length and restore
        # the mtime.  The old cache treated this metadata as proof that the file
        # was still authenticated and re-hashed only gpgv itself.
        sidecar.write_bytes(b"B" * 64)
        os.utime(sidecar, ns=(stat_before.st_atime_ns, stat_before.st_mtime_ns))

        tampered_fingerprint = openpgp_verifier.verifier_fingerprint(
            openpgp_verifier.enumerate_verifier_files(verifier_dir)
        )
        assert tampered_fingerprint == original_fingerprint

        with pytest.raises(openpgp_verifier.VerifierIntegrityError, match="libexample.dll"):
            openpgp_verifier.verify_bundled_gpg_integrity(
                verifier_dir,
                policy_path_fn=lambda: policy_path,
            )
    finally:
        openpgp_verifier.reset_verifier_integrity_cache()


def test_package_acquisition_uses_unc_aware_file_url_conversion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy file://server/share URLs must keep the UNC hostname during copy."""
    source = tmp_path / "source.rpm"
    payload = b"package payload"
    source.write_bytes(payload)
    destination = tmp_path / "destination.rpm"

    legacy_unc_url = "file://fileserver/share/repo/Packages/example.rpm"
    seen_urls: list[str] = []

    monkeypatch.setattr(
        package_acquisition,
        "repo_relative_url",
        lambda *_args, **_kwargs: legacy_unc_url,
    )

    def resolve_file_url(url: str) -> Path:
        seen_urls.append(url)
        return source

    monkeypatch.setattr(package_acquisition, "file_url_to_path", resolve_file_url, raising=False)

    package = SimpleNamespace(
        repo=SimpleNamespace(normalized_url="file://fileserver/share/repo"),
        location="Packages/example.rpm",
        nevra="example-1-1.x86_64",
        size=len(payload),
    )
    options = SimpleNamespace(retries=1)
    services = package_acquisition.AcquisitionServices(
        open_url=lambda *_args, **_kwargs: pytest.fail("network path should not be used"),
        verify_artifact=lambda *_args, **_kwargs: True,
    )

    package_acquisition.copy_or_download(
        package,
        destination,
        options,
        Reporter(),
        services,
    )

    assert seen_urls == [legacy_unc_url]
    assert destination.read_bytes() == payload
