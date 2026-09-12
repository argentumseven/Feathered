"""Exercise the extracted execution boundary with real artifacts and no Tk.

These tests supply a prepared BuildPlan. They do not claim the GUI's plan
preparation or the public CLI has been made headless.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def local_repository(tmp_path):
    if not all(shutil.which(tool) for tool in ("dpkg-deb", "dpkg-scanpackages")):
        pytest.skip("requires dpkg fixture tools")
    repo = tmp_path / "repository"
    index = repo / "dists/stable/main/binary-amd64"
    index.mkdir(parents=True)
    (repo / "pool").mkdir()
    for name, version in (("podman", "1.0"), ("podman", "1.1"), ("runit", "1.0")):
        source = tmp_path / f"{name}-{version}" / "DEBIAN"
        source.mkdir(parents=True)
        (source / "control").write_text(
            f"Package: {name}\nVersion: {version}\nArchitecture: amd64\n"
            "Maintainer: Fixture <test@example.invalid>\nDescription: fixture\n")
        subprocess.run(["dpkg-deb", "--build", str(source.parent),
                        str(repo / f"pool/{name}_{version}_amd64.deb")],
                       check=True, capture_output=True)
    raw = subprocess.run(["dpkg-scanpackages", "-m", "pool", "/dev/null"],
                         cwd=repo, check=True, capture_output=True).stdout
    (index / "Packages").write_bytes(raw)
    (repo / "dists/stable/Release").write_text(
        "Suite: stable\nCodename: stable\nComponents: main\nArchitectures: amd64\n"
        f"SHA256:\n {hashlib.sha256(raw).hexdigest()} {len(raw)} main/binary-amd64/Packages\n")
    return repo


HEADLESS_RUN = r'''
import builtins, copy, json, shutil, sys
from pathlib import Path
real_import = builtins.__import__
def guarded(name, *args, **kwargs):
    if name.split('.')[0] == 'tkinter':
        raise ImportError('Tk is forbidden in this execution test')
    return real_import(name, *args, **kwargs)
builtins.__import__ = guarded
from build_spec import (BuildSpec, TargetSpec, ContentSpec, SourceSpec, MirrorSpec,
                        OutputSpec, ExactPackageRecord, RepositoryRecord)
from core import RepoSpec, BuildOptions, Reporter
from acquisition_model import derive_acquisition_state
from source_readiness import evaluate_source_readiness
from feathered_app.build_services import BuildServices
from feathered_app.headless_host import HeadlessHost
from feathered_app.build_runner import BuildPlan, run
from feathered_app.spec_replay import resolve_exact_packages
repo_path, out_path, mode = sys.argv[1:]
repo = RepoSpec('Local', Path(repo_path).as_uri() + '/', 'dependency',
                repo_format='apt', suite='stable', components='main', allow_unverified_index=True)
mirror = mode in ('separate', 'unified')
exact = mode == 'exact'
devuan = mode == 'devuan'
repos = [repo]
if mirror:
    second = Path(repo_path).with_name('second-repository')
    shutil.copytree(repo_path, second)
    repos.append(RepoSpec('Second', second.as_uri() + '/', 'dependency',
        repo_format='apt', suite='stable', components='main', allow_unverified_index=True))
spec = BuildSpec(
    target=TargetSpec(distribution='Devuan' if devuan else 'Debian', release='12',
                      arch='amd64', init_system='runit' if devuan else ''),
    content=ContentSpec(selection_mode='Entire repository (mirror)' if mirror else
                        'Choose packages' if exact else 'Workload preset', workload='Podman',
                        package_version='Latest', exact_packages=(ExactPackageRecord(
                            'podman', '1.0', 'dependency', 'Local', 'amd64', repo.source_identity),) if exact else ()),
    sources=SourceSpec(method='Custom repositories', mirror_method='Custom mirror repositories',
                       repositories=tuple(RepositoryRecord.capture(r) for r in repos)),
    mirror=MirrorSpec(layout='unified' if mode == 'unified' else 'separate',
                      selected_repositories=tuple(r.source_identity for r in repos) if mirror else ()),
    output=OutputSpec(directory=out_path, folder_scheme='System and contents',
                      folder_stamp='date', emit_repository=True))
lines, progress = [], []
reporter = Reporter(log=lines.append, progress=lambda label, value: progress.append((label, value)))
host = HeadlessHost(spec, BuildServices(reporter=reporter, trust_policy=lambda rows: True), repos)
if exact:
    host.selected_packages = resolve_exact_packages(host, reporter)
state = derive_acquisition_state(host._acquisition_intent(),
    exact_root_count=len(host.selected_packages), exact_root_sources_ready=True,
    mirror_repository_count=len(host._selected_mirror_repositories()),
    workload_readiness=evaluate_source_readiness(host._source_plan(), repos, tier_getter=host._repo_tier))
assert not state.blocked, state.reason
requests = host._package_requests()
opts = BuildOptions(emit_repository=True)
forks = [(r.source_identity, host._folder_name(r), copy.deepcopy(opts)) for r in repos] if mirror else []
job = BuildPlan(state, opts, requests, host._request_source_plan_metadata(requests),
                repos, False, None, locked_mirror_publications=forks)
run(host, job)
events = []
while not host.events.empty(): events.append(host.events.get_nowait())
done = [event for event in events if event[0] == 'done']
assert len(done) == 1 and done[0][1] is True, (done, lines[-6:])
assert progress and all(0 <= value <= 1 for label, value in progress)
assert not any(name.startswith('tkinter') for name in sys.modules)
print(json.dumps({'output': done[0][3], 'init': host._selected_init_system(),
                  'source_method': host._active_source_method()}))
'''


@pytest.mark.parametrize("mode", ["workload", "exact", "separate", "unified", "devuan"])
def test_prepared_build_publishes_with_tk_blocked(local_repository, tmp_path, mode):
    output = tmp_path / "out"
    env = dict(os.environ)
    env.pop("DISPLAY", None)
    env.pop("WAYLAND_DISPLAY", None)
    result = subprocess.run([sys.executable, "-c", HEADLESS_RUN, str(local_repository),
                             str(output), mode], cwd=ROOT, env=env,
                            capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stdout + result.stderr
    record = json.loads(result.stdout)
    assert Path(record["output"]).is_dir()
    payloads = {p.name for p in output.rglob("*.deb")}
    if mode == "exact":
        assert "podman_1.0_amd64.deb" in payloads
        assert "podman_1.1_amd64.deb" not in payloads
    else:
        assert "podman_1.1_amd64.deb" in payloads
    if mode == "devuan":
        assert record["init"] == "runit"
        assert "runit_1.0_amd64.deb" in payloads
    if mode in ("separate", "unified"):
        assert record["source_method"] == "Custom mirror repositories"
        assert "podman_1.0_amd64.deb" in payloads
        folders = [p for p in output.iterdir() if p.is_dir() and not p.name.startswith(".")]
        assert len(folders) == (2 if mode == "separate" else 1)
        if mode == "unified":
            merged = json.loads(next(output.rglob("mirror-sources.json")).read_text())
            assert merged["retained_package_count"] == 3
            assert merged["duplicate_records_removed"] == 3
    assert list(output.rglob("manifest.json"))


def test_services_forward_progress_events_cancellation_and_conflict_details():
    import queue
    from build_spec import BuildSpec
    from core import Reporter
    from feathered_app.build_services import BuildServices
    from feathered_app.headless_host import HeadlessHost
    from feathered_app.build_runner import run

    progress, decisions = [], []
    events = queue.Queue()
    cancelled = {"value": False}
    services = BuildServices(
        Reporter(progress=lambda label, value: progress.append((label, value))),
        decision_policy=lambda title, text: decisions.append(text) or False,
        events=events, should_cancel=lambda: cancelled["value"])
    host = HeadlessHost(BuildSpec(), services)
    host._progress("Metadata", 0.4)
    assert progress == [("Metadata", 0.4)]
    assert not host._confirm_conflicts(["alpha conflicts with beta"])
    assert "alpha conflicts with beta" in decisions[0]
    cancelled["value"] = True
    # Cancellation must stop execution before a job is accessed or any I/O starts.
    run(host, None)
    assert events.get_nowait() == ("done", "cancelled", "Operation cancelled")


def test_frozen_signing_and_baseline_options_never_fall_back_to_controls():
    from build_spec import BuildSpec, SourceSpec, TargetSpec
    from core import Reporter
    from feathered_app.build_services import BuildServices
    from feathered_app.headless_host import HeadlessHost

    class ForbiddenControl:
        def get(self): raise AssertionError("read a live control despite a frozen request")

    for signing, baseline in (("release-key", "/baseline/manifest.json"), ("", "")):
        host = HeadlessHost(BuildSpec(sources=SourceSpec(signing_key=signing),
                                      target=TargetSpec(baseline_path=baseline)),
                            BuildServices(Reporter()))
        host.signing_key_var = ForbiddenControl()
        host.baseline_var = ForbiddenControl()
        assert host._selected_output_option("signing_key", "signing_key_var") == signing
        assert host._selected_output_option("baseline_path", "baseline_var") == baseline
