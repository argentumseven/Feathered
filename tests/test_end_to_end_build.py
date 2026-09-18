"""A complete build, driven headlessly, with the worker under a tripwire.

Until 1.2.12 nothing exercised the build path. Every defect in it therefore
reached an operator first: the Tk reads the worker performed on a background
thread were found only by attempting this, and one of them --- ``_profile()``
--- had its ``RuntimeError`` swallowed by the per-repository handler and
reported as "Enabled source could not be read", so a build failed blaming the
repository rather than Feathered.

This runs the real thing: a local APT repository on disk, the real ``App``, the
real ``start_build``, under a real ``mainloop`` so the worker can schedule onto
it. Every Tk variable is swapped for a tripwire first, so any widget read the
worker performs is recorded rather than merely risked.

Requires ``dpkg-deb`` and ``dpkg-scanpackages`` to build the fixture, so it runs
in the Debian conformance job rather than on the Windows release runner.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

requires_tools = pytest.mark.skipif(
    not (shutil.which("dpkg-deb") and shutil.which("dpkg-scanpackages")),
    reason="dpkg-deb and dpkg-scanpackages are needed to build the repository fixture")

requires_display = pytest.mark.skipif(
    not (sys.platform.startswith("win") or sys.platform == "darwin"
         or os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
    reason="no display; run under xvfb-run")


def build_repository(root: Path, name: str = "repo",
                     packages_wanted=(("demo-tool", "1.0"),)) -> Path:
    """A small but genuine APT repository: real .deb, real Packages, real Release."""
    repo = root / name
    (repo / "dists/stable/main/binary-amd64").mkdir(parents=True)
    (repo / "pool").mkdir()
    for package, version in packages_wanted:
        control = root / f"src-{name}-{package}" / "DEBIAN"
        control.mkdir(parents=True, exist_ok=True)
        (control / "control").write_text(
            f"Package: {package}\nVersion: {version}\nArchitecture: amd64\n"
            "Maintainer: t <t@example.invalid>\nDescription: fixture\n", encoding="utf-8")
        build_env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
        subprocess.run(["dpkg-deb", "--build", str(control.parent),
                        str(repo / f"pool/{package}_{version}_amd64.deb")],
                       check=True, capture_output=True, env=build_env)
    packages = subprocess.run(["dpkg-scanpackages", "-m", "pool", "/dev/null"],
                              cwd=repo, capture_output=True, text=True).stdout
    (repo / "dists/stable/main/binary-amd64/Packages").write_text(packages, encoding="utf-8")
    raw = packages.encode()
    (repo / "dists/stable/Release").write_text(
        "Suite: stable\nCodename: stable\nComponents: main\nArchitectures: amd64\n"
        f"SHA256:\n {hashlib.sha256(raw).hexdigest()} {len(raw)} "
        "main/binary-amd64/Packages\n", encoding="utf-8")
    return repo


class Tripwire:
    """Records any read of a Tk variable attributed to a non-main thread."""

    def __init__(self, name, variable, offences):
        self._name, self._variable, self._offences = name, variable, offences
        self._main = threading.main_thread()
        try:
            self._last = variable.get()
        except Exception:
            self._last = ""

    def get(self):
        if threading.current_thread() is not self._main:
            # Record and return rather than delegating: the real read is what
            # raises, and one pass should collect every offender.
            self._offences.append(self._name)
            return self._last
        self._last = self._variable.get()
        return self._last

    def set(self, value):
        return self._variable.set(value)

    def __getattr__(self, item):
        return getattr(self._variable, item)


@requires_tools
@requires_display
def test_a_complete_build_touches_no_widget_from_the_worker(tmp_path, monkeypatch):
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    repo = build_repository(tmp_path)

    import apt_core
    import app
    from core import RepoSpec
    from feathered_app.ui import theme

    for name in ("showerror", "showinfo", "showwarning"):
        monkeypatch.setattr(theme.messagebox, name, lambda *a, **k: None, raising=False)
    monkeypatch.setattr(theme.messagebox, "askyesno", lambda *a, **k: True, raising=False)

    window = app.App()
    offences: list[str] = []
    try:
        window.distro_var.set("Debian")
        window.update_idletasks()
        window.arch_var.set("amd64")
        window.selection_mode_var.set("Choose packages")
        window.update_idletasks()

        source = RepoSpec("Local", repo.as_uri() + "/", "dependency", repo_format="apt",
                          suite="stable", components="main", allow_unverified_index=True)
        window.repo_rows = [source]
        payload = (repo / "pool/demo-tool_1.0_amd64.deb").read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        window.selected_packages = [apt_core.DebPackage(
            "demo-tool", "amd64", "1.0", "pool/demo-tool_1.0_amd64.deb", "sha256", digest,
            source, digests={"sha256": digest}, size=len(payload))]
        window.out_var.set(str(tmp_path / "out"))
        # Answer the trust review without a dialog; the dialog itself is
        # covered by tests/test_review_dialog_lock.py.
        # Inject the decision rather than stubbing the dialog: this is how a
        # non-interactive caller answers, and it keeps the build path Tk-free.
        window.__dict__["_trust_policy"] = lambda findings: True

        def start():
            for name, value in list(window.__dict__.items()):
                if isinstance(value, tk.Variable):
                    window.__dict__[name] = Tripwire(name, value, offences)
            window.start_build(True)
            poll()

        ticks = {"n": 0}

        def poll():
            ticks["n"] += 1
            finished = (window.active_operation is None
                        and window.__dict__.get("_activity_state") in ("idle", "failed"))
            if finished or ticks["n"] > 1500:
                window.quit()
            else:
                window.after(20, poll)

        window.after(50, start)
        window.mainloop()

        assert window.__dict__.get("_activity_state") == "idle", (
            "the build should complete: " + " | ".join(window.log_lines[-5:]))
        output = Path(window.last_output_path)
        assert output.exists()
        assert (output / "debs" / "demo-tool_1.0_amd64.deb").exists()
        # emit_repository defaults off for a package workflow since 1.2.10, so\n        # install-offline.sh is only emitted when repository metadata is asked\n        # for. The payload and its provenance are the deliverable here.\n        assert list(output.glob("*.txt")) or (output / "debs").is_dir()
        assert offences == [], (
            "the build worker read Tk variables, which is undefined behaviour "
            "off the main thread: " + ", ".join(sorted(set(offences))))
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


def _run_to_completion(window):
    """Start the build and pump a real mainloop until the operation ends."""
    ticks = {"n": 0}

    def poll():
        ticks["n"] += 1
        finished = (window.active_operation is None
                    and window.__dict__.get("_activity_state") in ("idle", "failed"))
        if finished or ticks["n"] > 1500:
            window.quit()
        else:
            window.after(20, poll)

    window.after(50, lambda: (window.start_build(True), poll()))
    window.mainloop()


@requires_tools
@requires_display
@pytest.mark.parametrize("layout", ["separate", "unified"])
def test_a_repository_mirror_build_completes(tmp_path, monkeypatch, layout):
    """The mirror layouts, neither of which had ever been executed end to end.

    The unified layout in particular ships de-duplication, conflict refusal and
    a provenance record that until now existed only under unit tests: no test
    had ever produced an actual unified mirror on disk.

    Both repositories publish an identical `shared` package, so the unified run
    exercises a real cross-repository merge rather than a trivial union.
    """
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    first = build_repository(tmp_path, "repoA", (("shared", "1.0"), ("only-a", "1.0")))
    second = build_repository(tmp_path, "repoB", (("shared", "1.0"), ("only-b", "1.0")))

    import app
    from acquisition_model import MIRROR_LAYOUT_LABELS, MirrorLayout
    from core import RepoSpec
    from feathered_app.ui import theme

    for name in ("showerror", "showinfo", "showwarning"):
        monkeypatch.setattr(theme.messagebox, name, lambda *a, **k: None, raising=False)
    monkeypatch.setattr(theme.messagebox, "askyesno", lambda *a, **k: True, raising=False)

    window = app.App()
    offences: list[str] = []
    try:
        window.distro_var.set("Debian")
        window.update_idletasks()
        window.arch_var.set("amd64")
        window.selection_mode_var.set("Entire repository (mirror)")
        window.update_idletasks()

        rows = [RepoSpec(label, source.as_uri() + "/", "dependency", repo_format="apt",
                         suite="stable", components="main", allow_unverified_index=True)
                for label, source in (("RepoA", first), ("RepoB", second))]
        window.repo_rows = rows
        window.mirror_repos = {row.source_identity for row in rows}
        window.mirror_layout_var.set(MIRROR_LAYOUT_LABELS[
            MirrorLayout.UNIFIED if layout == "unified" else MirrorLayout.SEPARATE])
        window.out_var.set(str(tmp_path / "out"))
        # Inject the decision rather than stubbing the dialog: this is how a
        # non-interactive caller answers, and it keeps the build path Tk-free.
        window.__dict__["_trust_policy"] = lambda findings: True

        original_start = window.start_build

        def armed(*args, **kwargs):
            for name, value in list(window.__dict__.items()):
                if isinstance(value, tk.Variable):
                    window.__dict__[name] = Tripwire(name, value, offences)
            return original_start(*args, **kwargs)

        window.start_build = armed
        _run_to_completion(window)

        assert window.__dict__.get("_activity_state") == "idle", (
            "the mirror build should complete: " + " | ".join(window.log_lines[-5:]))
        assert offences == [], (
            "the mirror worker read Tk variables: " + ", ".join(sorted(set(offences))))

        out = Path(tmp_path / "out")
        if layout == "separate":
            folders = sorted(p.name for p in out.iterdir()
                             if p.is_dir() and not p.name.startswith("."))
            assert len(folders) == 2, f"one faithful folder per repository, got {folders}"
            assert all("mirror-Repo" in name for name in folders)
        else:
            published = Path(window.last_output_path)
            note = (published / "UNIFIED-MIRROR.txt").read_text(encoding="utf-8")
            assert "not a copy of any single one of them" in note
            record = json.loads(
                (published / "debs" / "mirror-sources.json").read_text(encoding="utf-8"))
            assert record["retained_package_count"] == 3, "shared must be kept once"
            assert record["duplicate_records_removed"] == 1
            merged = [row for row in record["packages"] if row["also_published_by"]]
            assert len(merged) == 1
            assert merged[0]["merge_basis"] == "strong", (
                "an identical artifact must be merged on digest proof, not priority")
            assert merged[0]["also_published_by"] == ["RepoB"]
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


@requires_tools
@requires_display
def test_a_workload_preset_build_completes(tmp_path, monkeypatch):
    """The path most operators actually use, and the last one uncovered.

    Workload mode resolves a preset's roots rather than explicit packages, so it
    reaches request construction, version pinning and dependency-mode handling
    that the exact-package and mirror paths never touch. Three more worker-thread
    Tk reads lived there: arch_var via materialize_source_plan, and mode_var and
    package_version_var via request construction and _parameter_signature.
    """
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    repo = build_repository(tmp_path, "repo", (("podman", "4.3.1"), ("libc-dep", "1.0")))

    import app
    from core import RepoSpec
    from feathered_app.ui import theme

    for name in ("showerror", "showinfo", "showwarning"):
        monkeypatch.setattr(theme.messagebox, name, lambda *a, **k: None, raising=False)
    monkeypatch.setattr(theme.messagebox, "askyesno", lambda *a, **k: True, raising=False)

    window = app.App()
    offences: list[str] = []
    try:
        window.distro_var.set("Debian")
        window.update_idletasks()
        window.arch_var.set("amd64")
        window.selection_mode_var.set("Workload preset")
        window.update_idletasks()
        window.workload_var.set("Podman")
        window.update_idletasks()

        window.repo_rows = [RepoSpec("Local", repo.as_uri() + "/", "dependency",
                                     repo_format="apt", suite="stable", components="main",
                                     allow_unverified_index=True)]
        window.out_var.set(str(tmp_path / "out"))
        # Inject the decision rather than stubbing the dialog: this is how a
        # non-interactive caller answers, and it keeps the build path Tk-free.
        window.__dict__["_trust_policy"] = lambda findings: True

        original_start = window.start_build

        def armed(*args, **kwargs):
            for name, value in list(window.__dict__.items()):
                if isinstance(value, tk.Variable):
                    window.__dict__[name] = Tripwire(name, value, offences)
            return original_start(*args, **kwargs)

        window.start_build = armed
        _run_to_completion(window)

        assert window.__dict__.get("_activity_state") == "idle", (
            "the workload build should complete: " + " | ".join(window.log_lines[-5:]))
        output = Path(window.last_output_path)
        assert (output / "debs" / "podman_4.3.1_amd64.deb").exists(), (
            "the preset root must be resolved and downloaded")
        assert offences == [], (
            "the workload worker read Tk variables: " + ", ".join(sorted(set(offences))))
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


@requires_tools
@requires_display
def test_the_cli_builds_the_same_bundle_from_a_saved_spec(tmp_path, monkeypatch, capsys):
    """A build without a person clicking, from a spec the GUI produced.

    The point of the CLI is that scheduled rebuilds stop needing an operator,
    so this asserts the whole loop: capture a request from a real window, write
    it to disk, and have feathered_cli produce a bundle from that file alone.
    """
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    repo = build_repository(tmp_path, "repo", (("podman", "4.3.1"),))

    import app
    import build_spec
    import feathered_cli
    from core import RepoSpec

    window = app.App()
    try:
        window.distro_var.set("Debian")
        window.update_idletasks()
        # This fixture represents a completed target selection. capture() also
        # accepts drafts, but preparation deliberately rejects an empty release
        # before reaching trust review. Do not rely on startup/discovery defaults.
        window.release_var.set("12")
        window.arch_var.set("amd64")
        window.selection_mode_var.set("Workload preset")
        window.update_idletasks()
        window.workload_var.set("Podman")
        window.update_idletasks()
        window.repo_rows = [RepoSpec("Local", repo.as_uri() + "/", "dependency",
                                     repo_format="apt", suite="stable", components="main",
                                     allow_unverified_index=True)]
        window.out_var.set(str(tmp_path / "out"))
        spec_file = tmp_path / "build.json"
        captured_spec = build_spec.capture(window)
        assert captured_spec.target.release == "12"
        spec_file.write_text(captured_spec.to_json(), encoding="utf-8")
    finally:
        window.destroy()

    # show and --dry-run must not touch the network or the filesystem.
    assert feathered_cli.main(["show", "--spec", str(spec_file)]) == 0
    assert "Podman" in capsys.readouterr().out
    assert feathered_cli.main(["build", "--spec", str(spec_file), "--dry-run"]) == 0
    assert not (tmp_path / "out").exists(), "a dry run must write nothing"

    # Unattended runs decline trust findings rather than accepting them silently.
    assert feathered_cli.main(["build", "--spec", str(spec_file), "--quiet"]) == 2
    captured = capsys.readouterr()
    assert "TRUST:" in captured.err, "a declined run must say what it refused"

    assert feathered_cli.main(
        ["build", "--spec", str(spec_file), "--quiet", "--accept-trust-findings"]) == 0
    bundles = [p for p in (tmp_path / "out").iterdir() if p.is_dir()
               and not p.name.startswith(".")]
    assert len(bundles) == 1
    assert (bundles[0] / "debs" / "podman_4.3.1_amd64.deb").exists()


def test_the_cli_does_not_report_success_without_a_bundle(tmp_path, monkeypatch, capsys):
    """A CLI success result must always identify a published bundle.

    `start_build` returns early when validation rejects the request, leaving the
    window in its initial idle state having built nothing. The CLI suppresses
    error dialogs, so it read that idle state as success. A scheduled rebuild
    reporting success without producing a bundle is the worst failure this tool
    can have, so success now requires a published directory that exists.
    """
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    import build_spec
    import feathered_cli

    # A spec with no repositories at all: the request cannot be satisfied, and
    # validation rejects it before any build begins.
    spec_file = tmp_path / "empty.json"
    spec_file.write_text(build_spec.BuildSpec().to_json(), encoding="utf-8")

    code = feathered_cli.main(["build", "--spec", str(spec_file), "--quiet"])

    assert code != 0, "a run that produced no bundle must not exit zero"
    assert code == 5
    assert "recognized target distribution" in capsys.readouterr().err


@requires_tools
@requires_display
def test_a_unified_mirror_replays_from_a_saved_spec(tmp_path, monkeypatch):
    """Replay must reproduce the build, not merely round-trip the JSON.

    `apply` did not restore the mirror layout or disagreement policy, so a saved
    unified mirror replayed as a separate-folder one - a serialization test
    passed while the rebuild produced something different.
    """
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir(parents=True, exist_ok=True)

    import app
    import build_spec
    from acquisition_model import MIRROR_LAYOUT_LABELS, MirrorLayout
    from core import RepoSpec
    from mirror_unification import MERGE_POLICY_LABELS, MergePolicy

    window = app.App()
    try:
        window.selection_mode_var.set("Entire repository (mirror)")
        window.update_idletasks()
        window.mirror_layout_var.set(MIRROR_LAYOUT_LABELS[MirrorLayout.UNIFIED])
        window.mirror_conflict_policy_var.set(
            MERGE_POLICY_LABELS[MergePolicy.PREFER_PRIORITY])
        source = RepoSpec("Vendor", "https://vendor.invalid/", "dependency")
        source.evidence_urls = ["https://vendor.invalid/advisory"]
        source.redirect_allow_origins = ["https://cdn.vendor.invalid"]
        window.repo_rows = [source]
        spec = build_spec.capture(window)
    finally:
        window.destroy()

    restored = build_spec.BuildSpec.from_json(spec.to_json())
    assert restored.mirror.layout == "unified"
    assert restored.mirror.disagreement_policy == "prefer-priority"

    replayed = app.App()
    try:
        build_spec.apply(replayed, restored)
        replayed.update_idletasks()
        assert replayed._mirror_layout() is MirrorLayout.UNIFIED, (
            "a replayed unified mirror must not become a separate-folder one")
        assert replayed._merge_policy() is MergePolicy.PREFER_PRIORITY

        rebuilt = build_spec.repositories_from(restored, RepoSpec)[0]
        assert list(rebuilt.evidence_urls) == ["https://vendor.invalid/advisory"], (
            "evidence sources must survive replay")
        assert list(rebuilt.redirect_allow_origins) == ["https://cdn.vendor.invalid"], (
            "a replayed build must not run with an empty redirect allow-list")
    finally:
        replayed.destroy()


@requires_tools
def test_cli_replays_an_exact_package_into_a_real_bundle(tmp_path, monkeypatch):
    """Saved root identities must become real selections before GUI validation."""
    for variable in ("APPDATA", "XDG_CONFIG_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / "state"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    repo_path = build_repository(tmp_path, "repo", (("podman", "1.0"), ("podman", "1.1")))
    from build_spec import (BuildSpec, ContentSpec, ExactPackageRecord, OutputSpec,
                            RepositoryRecord, SourceSpec, TargetSpec)
    from core import RepoSpec
    from feathered_cli import run_build
    repo = RepoSpec("Local", repo_path.as_uri() + "/", "dependency", repo_format="apt",
                    suite="stable", components="main", allow_unverified_index=True)
    spec = BuildSpec(
        target=TargetSpec(distribution="Debian", release="12", arch="amd64"),
        content=ContentSpec(selection_mode="Choose packages", exact_packages=(
            ExactPackageRecord("podman", "1.0", "dependency", "Local", "amd64", repo.source_identity),)),
        sources=SourceSpec(repositories=(RepositoryRecord.capture(repo),)),
        output=OutputSpec(directory=str(tmp_path / "out"), folder_scheme="System and contents",
                          folder_stamp="date", emit_repository=False))
    assert run_build(BuildSpec.from_json(spec.to_json()), quiet=True, accept_trust=True) == 0
    payloads = {path.name for path in (tmp_path / "out").rglob("*.deb")}
    assert "podman_1.0_amd64.deb" in payloads
    assert "podman_1.1_amd64.deb" not in payloads
