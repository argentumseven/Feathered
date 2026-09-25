"""Regressions for the September 2026 review follow-ups."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

import apt_core
import arch_core
import bundle_baseline
import core
import installer
import provenance
import repository_tools
import repository_transport
from core import BuildOptions, Package, RepoSpec, Reporter

BASH = shutil.which("bash")


# ---- fixtures ---------------------------------------------------------------

def _rpm_bundle(root: Path, options: BuildOptions | None = None) -> Path:
    payload = root / "demo.rpm"
    payload.write_bytes(b"rpm-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/")
    pkg = Package("demo", "x86_64", "0", "1", "1", "demo.rpm", "sha256",
                  hashlib.sha256(payload.read_bytes()).hexdigest(), repo,
                  size=payload.stat().st_size)
    out = root / "bundle"
    core.write_bundle(core.ResolutionResult([pkg], [], [pkg]), out,
                      options or BuildOptions(retries=1), Reporter(), {"workload": "t"})
    return out


def _deb_bundle(root: Path) -> Path:
    payload = root / "demo.deb"
    payload.write_bytes(b"deb-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/", repo_format="apt", suite="stable",
                    components="main")
    deb = apt_core.DebPackage("demo", "amd64", "1.0", "demo.deb", "sha256",
                              hashlib.sha256(payload.read_bytes()).hexdigest(), repo,
                              size=payload.stat().st_size)
    out = root / "bundle"
    apt_core.write_bundle(apt_core.DebResolutionResult([deb], [], [deb]), out,
                          BuildOptions(retries=1), Reporter(), {"workload": "t"})
    return out


def _arch_bundle(root: Path) -> Path:
    payload = root / "demo-1.0-x86_64.pkg.tar.zst"
    payload.write_bytes(b"arch-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/", repo_format="arch")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    pkg = arch_core.ArchPackage(name="demo", arch="x86_64", version="1.0",
                                location=payload.name, checksum_type="sha256",
                                checksum=digest, repo=repo, digests={"sha256": digest},
                                size=payload.stat().st_size)
    out = root / "bundle"
    arch_core.write_bundle(arch_core.ArchResolutionResult([pkg], [], [pkg]), out,
                           BuildOptions(retries=1), Reporter(), {"workload": "t"})
    return out


# ---- RPM installer: target-side signature enforcement is on by default -------

def test_rpm_installer_enforces_gpgcheck_without_build_side_keyring(tmp_path):
    script = (_rpm_bundle(tmp_path) / "install-offline.sh").read_text(encoding="utf-8")
    assert "GPGCHECK=1" in script
    assert "gpgcheck=$GPGCHECK" in script
    assert "\ngpgcheck=0" not in script and "\nlocalpkg_gpgcheck=0" not in script
    # The override still exists, and is the only way to turn checking off.
    assert '[ "${FEATHERED_ALLOW_UNSIGNED:-0}" = 1 ]' in script


@pytest.mark.skipif(BASH is None, reason="GNU bash is required")
@pytest.mark.parametrize("override,expected", [("", "1"), ("1", "0")])
def test_rpm_installer_override_is_the_only_switch(tmp_path, override, expected):
    script = (_rpm_bundle(tmp_path) / "install-offline.sh").read_text(encoding="utf-8")
    start = script.index("GPGCHECK=1")
    end = script.index("\nfi\n", start) + 4
    env = {"PATH": "/usr/bin:/bin"}
    if override:
        env["FEATHERED_ALLOW_UNSIGNED"] = override
    proc = subprocess.run([BASH, "-c", "set -euo pipefail\n" + script[start:end] + 'printf %s "$GPGCHECK"'],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == expected


# ---- APT installer: unverified archive chains are gated like RPM/pacman ------

def test_apt_installer_gates_an_unauthenticated_release_chain(tmp_path):
    script = (_deb_bundle(tmp_path) / "install-offline.sh").read_text(encoding="utf-8")
    gate = script.index('if [ "${FEATHERED_ALLOW_UNSIGNED:-0}" != 1 ]')
    assert gate < script.index("sudo apt-get")


def test_deb_chain_verification_requires_evidence():
    ok = SimpleNamespace(assurance=provenance.VERIFIED_ARCHIVE)
    bad = SimpleNamespace(assurance=provenance.UNVERIFIED)
    assert installer._deb_chain_verified([ok, ok])
    assert not installer._deb_chain_verified([ok, bad])
    assert not installer._deb_chain_verified([])
    assert not installer._deb_chain_verified(None)


# ---- pacman installer honours the target's own [options] ---------------------

@pytest.mark.skipif(BASH is None, reason="GNU bash is required")
def test_pacman_config_inherits_system_options_and_drops_system_repos(tmp_path):
    script = (_arch_bundle(tmp_path) / "install-offline.sh").read_text(encoding="utf-8")
    start = script.index('TMP_CONF="$(mktemp)"')
    end = script.index("# The builder includes")
    system = tmp_path / "pacman.conf"
    system.write_text("# header\n[options]\nHoldPkg = pacman glibc\nIgnorePkg = linux\n"
                      "NoUpgrade = etc/keep.conf\nArchitecture = auto\n\n"
                      "[core]\nInclude = /etc/pacman.d/mirrorlist\n", encoding="utf-8")
    fragment = script[start:end].replace("/etc/pacman.conf", str(system))
    proc = subprocess.run([BASH, "-c", "set -euo pipefail\nHERE_URL=/b\n" + fragment + 'cat "$TMP_CONF"'],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    conf = proc.stdout
    for line in ("IgnorePkg = linux", "HoldPkg = pacman glibc", "NoUpgrade = etc/keep.conf"):
        assert line in conf
    assert "[core]" not in conf and "mirrorlist" not in conf
    assert "[feathered]" in conf and "Server = file:///b/packages" in conf


# ---- RPM provenance keeps the digest axis on the keyring path ----------------

def test_vendor_verified_rpm_retains_acquisition_digest_axis(tmp_path, monkeypatch):
    keyring = tmp_path / "vendor.gpg"
    keyring.write_bytes(b"not-a-real-keyring")
    monkeypatch.setattr(provenance, "verify_rpm_package",
                        lambda path, ring, reporter: {"key_id": "FD431D51B4B5F9B4",
                                                      "signer": "Fixture", "algorithm": "RSA"})
    out = _rpm_bundle(tmp_path, BuildOptions(retries=1, vendor_keyring=str(keyring)))
    record = json.loads(next(out.rglob("provenance.json")).read_text(encoding="utf-8"))
    entry = record["packages"][0]
    assert entry["assurance"] == provenance.VERIFIED_VENDOR
    assert entry["digest_checked"] is True
    assert entry["content_provenance"] == provenance.PROVENANCE_ACQUISITION_DIGEST


# ---- transport does not retry deterministic failures -------------------------

class _Recorder:
    def __init__(self):
        self.lines = []

    def log(self, message):
        self.lines.append(message)

    def check_cancel(self):
        pass


class _Body(io.BytesIO):
    headers: dict = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize("failure", [
    lambda: urllib.error.HTTPError("https://x.invalid/a", 404, "Not Found", {}, None),
    lambda: urllib.error.HTTPError("https://x.invalid/a", 403, "Forbidden", {}, None),
    "oversize",
])
def test_deterministic_fetch_failures_are_not_retried(monkeypatch, failure):
    monkeypatch.setattr(repository_transport.time, "sleep", lambda s: None)
    calls = []

    def opener(url, timeout, repo):
        calls.append(url)
        if failure == "oversize":
            return _Body(b"x" * 64)
        raise failure()

    with pytest.raises(RuntimeError):
        repository_transport.fetch_bytes("https://x.invalid/a", _Recorder(), retries=3,
                                         max_bytes=16, open_url_fn=opener,
                                         redact_url_fn=lambda u: u)
    assert len(calls) == 1


def test_transient_fetch_failures_are_still_retried(monkeypatch):
    monkeypatch.setattr(repository_transport.time, "sleep", lambda s: None)
    calls = []

    def opener(url, timeout, repo):
        calls.append(url)
        if len(calls) < 3:
            raise urllib.error.HTTPError(url, 503, "Unavailable", {}, None)
        return _Body(b"payload")

    got = repository_transport.fetch_bytes("https://x.invalid/a", _Recorder(), retries=3,
                                           open_url_fn=opener, redact_url_fn=lambda u: u)
    assert got == b"payload" and len(calls) == 3


# ---- deb control member lookup matches a prefix, not a character set ---------

def _deb_with_control(tmp_path: Path, member_name: str) -> Path:
    control = io.BytesIO()
    with tarfile.open(fileobj=control, mode="w") as tf:
        data = b"Package: demo\nVersion: 1.0\nArchitecture: amd64\n"
        info = tarfile.TarInfo(member_name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    body = control.getvalue()
    ar = io.BytesIO()
    ar.write(b"!<arch>\n")
    for name, content in ((b"debian-binary", b"2.0\n"), (b"control.tar", body)):
        header = name.ljust(16) + b"0".ljust(12) + b"0".ljust(6) + b"0".ljust(6) \
            + b"100644".ljust(8) + str(len(content)).encode().ljust(10) + b"`\n"
        ar.write(header + content + (b"\n" if len(content) % 2 else b""))
    path = tmp_path / "demo.deb"
    path.write_bytes(ar.getvalue())
    return path


@pytest.mark.parametrize("name", ["control", "./control"])
def test_deb_control_is_found_under_normal_names(tmp_path, name):
    fields = repository_tools._read_deb_control(_deb_with_control(tmp_path, name))
    assert fields["Package"] == "demo"


@pytest.mark.parametrize("name", [".control", "..control"])
def test_deb_control_lookup_does_not_strip_characters(tmp_path, name):
    with pytest.raises(RuntimeError, match="control file not found"):
        repository_tools._read_deb_control(_deb_with_control(tmp_path, name))


# ---- differential baselines report incomparable digests ---------------------

def test_incomparable_baseline_digests_are_reported():
    digest = lambda algorithm, value: (algorithm, value) if algorithm and value else None
    pkg = SimpleNamespace(name="a", nevra="a-1", checksum_type="sha512",
                          checksum="f" * 128, verification=None)
    incomparable: list[str] = []
    ship, skip, _ = bundle_baseline.partition(
        [pkg], {"a-1": "e" * 64}, digest=digest, matches=lambda x, y: x == y,
        incomparable=incomparable)
    assert ship == [pkg] and skip == [] and incomparable == ["a-1"]
