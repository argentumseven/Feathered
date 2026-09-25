"""The generated installer must address the bundle as a URL, not as a path.

The failure this pins is silent, which is why it needs its own module. Given a
bundle directory containing a space, the pre-1.2.5 installer wrote

    deb [trusted=yes] file:/media/user/My Passport feathered main

APT parses that as URI ``file:/media/user/My``, suite ``Passport``, components
``feathered main``. It looks up a suite that does not exist, ignores every
index, and still exits 0 from ``apt-get update``. The operator finds out on the
far side of an air gap, from an "unable to locate package" message that names
none of this. ``bash -n`` cannot catch it because the script is valid shell;
the URL is what is wrong.

These tests therefore execute the emitted encoding step under bash rather than
asserting on the script text, and pin the property that makes the change safe:
a URL-safe path must encode to itself.
"""
from __future__ import annotations

import hashlib
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import apt_core
import arch_core
import core
from core import BuildOptions, Package, RepoSpec, Reporter

AWKWARD = "aw kward #dir 100%"


def _bash_candidates() -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str | None) -> None:
        if not value:
            return
        key = os.path.normcase(os.path.abspath(value))
        if key in seen:
            return
        seen.add(key)
        candidates.append(value)

    if os.name == "nt":
        git = shutil.which("git")
        if git:
            root = Path(git).resolve().parent.parent
            add(str(root / "bin" / "bash.exe"))
            add(str(root / "usr" / "bin" / "bash.exe"))
        for variable in ("ProgramFiles", "ProgramW6432"):
            base = os.environ.get(variable)
            if base:
                add(str(Path(base) / "Git" / "bin" / "bash.exe"))
                add(str(Path(base) / "Git" / "usr" / "bin" / "bash.exe"))
    add(shutil.which("bash"))
    return candidates


def _usable_bash() -> str | None:
    for candidate in _bash_candidates():
        try:
            proc = subprocess.run([candidate, "--version"], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0 and b"GNU bash" in proc.stdout + proc.stderr:
            return candidate
    return None


def _bash_path(path: Path | str) -> str:
    value = str(Path(path).resolve())
    if os.name == "nt" and len(value) >= 3 and value[1] == ":":
        return "/" + value[0].lower() + value[2:].replace("\\", "/")
    return value


def _python3_prelude() -> str:
    if os.name != "nt":
        return ""
    executable = shlex.quote(_bash_path(sys.executable))
    return f"python3() {{ MSYS2_ARG_CONV_EXCL='*' {executable} \"$@\"; }}\n"


BASH = _usable_bash()


def test_bash_discovery_rejects_non_gnu_launcher(monkeypatch):
    monkeypatch.setattr(sys.modules[__name__], "_bash_candidates",
                        lambda: ["windows-wsl-bash", "git-bash"])

    def fake_run(command, **kwargs):
        if command[0] == "windows-wsl-bash":
            return subprocess.CompletedProcess(command, 1, b"\xff\xfeW\x00S\x00L\x00", b"")
        return subprocess.CompletedProcess(command, 0, b"GNU bash, version 5.2", b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _usable_bash() == "git-bash"


def _rpm_bundle(root: Path) -> Path:
    payload = root / "demo.rpm"
    payload.write_bytes(b"rpm-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/")
    pkg = Package("demo", "x86_64", "0", "1", "1", "demo.rpm", "sha256",
                  hashlib.sha256(payload.read_bytes()).hexdigest(), repo,
                  size=payload.stat().st_size)
    out = root / "bundle"
    core.write_bundle(core.ResolutionResult([pkg], [], [pkg]), out,
                      BuildOptions(retries=1), Reporter(), {"workload": "url-check"})
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
                          BuildOptions(retries=1), Reporter(), {"workload": "url-check"})
    return out


def _arch_bundle(root: Path) -> Path:
    payload = root / "demo-1.0-x86_64.pkg.tar.zst"
    payload.write_bytes(b"arch-fixture")
    repo = RepoSpec("Local", root.as_uri() + "/", repo_format="arch")
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    pkg = arch_core.ArchPackage(
        name="demo", arch="x86_64", version="1.0",
        location="demo-1.0-x86_64.pkg.tar.zst", checksum_type="sha256",
        checksum=digest, repo=repo, digests={"sha256": digest},
        size=payload.stat().st_size)
    pkg.provides = [arch_core.ArchRelation("demo", "=", "1.0", "provides")]
    out = root / "bundle"
    arch_core.write_bundle(arch_core.ArchResolutionResult([pkg], [], [pkg]), out,
                           BuildOptions(retries=1), Reporter(), {"workload": "url-check"})
    return out


BUILDERS = {"rpm": _rpm_bundle, "deb": _deb_bundle, "arch": _arch_bundle}
URL_LINES = {
    "rpm": "baseurl=file://$HERE_URL",
    "deb": '"$HERE_URL" > "$TMP_APT/feathered.list"',
    "arch": "Server = file://$HERE_URL/packages",
}


def _script(tmp_path: Path, family: str) -> str:
    root = tmp_path / family
    root.mkdir()
    return (BUILDERS[family](root) / "install-offline.sh").read_text(encoding="utf-8")


@pytest.mark.parametrize("family", sorted(BUILDERS))
def test_bundle_path_reaches_the_package_manager_as_a_url(tmp_path, family):
    """No family may interpolate the raw path into a file: URL."""
    script = _script(tmp_path, family)
    assert URL_LINES[family] in script
    assert "file://$HERE\n" not in script
    assert 'file:%s feathered main\\n\' "$HERE"' not in script


@pytest.mark.parametrize("family", sorted(BUILDERS))
def test_encoder_runs_before_any_privileged_step(tmp_path, family):
    """HERE_URL must be established before the family block that consumes it."""
    script = _script(tmp_path, family)
    assert script.index('HERE_URL="$(python3') < script.index("$HERE_URL", script.index("HERE_URL=") + 40)
    assert "command -v python3" in script


@pytest.mark.skipif(BASH is None, reason="GNU bash is required")
@pytest.mark.parametrize("path,expected", [
    ("/plain/bundle-path_1.0~rc", "/plain/bundle-path_1.0~rc"),
    ("/media/user/My Passport/bundle", "/media/user/My%20Passport/bundle"),
    ("/srv/100% full/bundle", "/srv/100%25%20full/bundle"),
    ("/srv/tag#3/bundle", "/srv/tag%233/bundle"),
    ("/srv/ünïcode/bundle", "/srv/%C3%BCn%C3%AFcode/bundle"),
])
def test_emitted_encoder_produces_a_usable_file_url(tmp_path, path, expected):
    """Run the encoding step Feathered emits, not a reimplementation of it.

    The first case is the safety property: a URL-safe path must survive
    unchanged, so this change cannot regress a bundle that installs today.
    """
    script = _script(tmp_path, "deb")
    start = script.index('HERE_URL="$(python3')
    end = script.index('\nfi\n', start) + 4
    harness = (f'set -euo pipefail\nHERE={path!r}\n' + _python3_prelude() +
               script[start:end] + 'printf "%s" "$HERE_URL"\n')
    proc = subprocess.run([BASH, "-c", harness], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == expected


@pytest.mark.skipif(BASH is None, reason="GNU bash is required")
def test_apt_installer_refuses_an_unindexed_bundle_repository(tmp_path):
    """`apt-get update` exits 0 on a misparsed source, so a guard must follow it."""
    script = _script(tmp_path, "deb")
    guard = script[script.index("sudo apt-get \"${APT_OPTS[@]}\" update"):]
    assert "indextargets" in guard
    assert "exit 1" in guard
    assert guard.index("indextargets") < guard.index("--simulate")


@pytest.mark.skipif(BASH is None, reason="GNU bash is required")
def test_awkward_bundle_directory_still_produces_a_valid_script(tmp_path):
    """The build host may itself sit under an awkward path."""
    root = tmp_path / AWKWARD
    root.mkdir()
    script = (_deb_bundle(root) / "install-offline.sh")
    proc = subprocess.run([BASH, "-n"], input=script.read_text(encoding="utf-8"),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr



# ---- review follow-ups that need a shell ------------------------------------
# These live here, not in test_review_followups.py, because this module owns the
# Windows-aware bash discovery (_usable_bash rejects the System32 WSL stub),
# path translation (_bash_path) and the release gate's permitted skip for a
# host without GNU bash.

@pytest.mark.skipif(BASH is None, reason="GNU bash is required")
@pytest.mark.parametrize("override,expected", [("", "1"), ("1", "0")])
def test_rpm_installer_signature_override_is_the_only_switch(tmp_path, override, expected):
    """gpgcheck defaults on; only FEATHERED_ALLOW_UNSIGNED=1 turns it off."""
    script = _script(tmp_path, "rpm")
    start = script.index("GPGCHECK=1")
    end = script.index("\nfi\n", start) + 4
    env = dict(os.environ)
    env.pop("FEATHERED_ALLOW_UNSIGNED", None)
    if override:
        env["FEATHERED_ALLOW_UNSIGNED"] = override
    proc = subprocess.run([BASH, "-c", "set -euo pipefail\n" + script[start:end] + 'printf %s "$GPGCHECK"'],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == expected


@pytest.mark.skipif(BASH is None, reason="GNU bash is required")
def test_pacman_config_inherits_system_options_and_drops_system_repos(tmp_path):
    """The temporary pacman.conf keeps IgnorePkg/HoldPkg/NoUpgrade, not repos."""
    script = _script(tmp_path, "arch")
    start = script.index('TMP_CONF="$(mktemp)"')
    end = script.index("# The builder includes")
    system = tmp_path / "pacman.conf"
    system.write_bytes(b"# header\n[options]\nHoldPkg = pacman glibc\nIgnorePkg = linux\n"
                       b"NoUpgrade = etc/keep.conf\nArchitecture = auto\n\n"
                       b"[core]\nInclude = /etc/pacman.d/mirrorlist\n")
    # A Windows path pasted raw into bash loses its backslashes; translate and quote.
    fragment = script[start:end].replace("/etc/pacman.conf", shlex.quote(_bash_path(system)))
    proc = subprocess.run([BASH, "-c", "set -euo pipefail\nHERE_URL=/b\n" + fragment + 'cat "$TMP_CONF"'],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    conf = proc.stdout
    for line in ("IgnorePkg = linux", "HoldPkg = pacman glibc", "NoUpgrade = etc/keep.conf"):
        assert line in conf
    assert "[core]" not in conf and "mirrorlist" not in conf
    assert "[feathered]" in conf and "Server = file:///b/packages" in conf
