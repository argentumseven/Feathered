"""Background observations and real metadata retain exact patch/build identities."""
from queue import Queue
from types import SimpleNamespace
import threading
import tkinter as tk
from unittest.mock import Mock

import pytest
import apt_core
import core
from k8s_discovery import discover
from workloads import load_workloads
from feathered_app.ui.kubernetes import KubernetesWorkloadMixin
from feathered_app.application.discovery import DiscoveryMixin


def test_minor_discovery_publishes_before_slowest_probe_finishes():
    slow = threading.Event()
    progress = threading.Event()
    results = []
    def probe(url):
        if '/v1.24/' in url:
            assert slow.wait(3)
            return True
        return '/v1.25/' in url
    worker = threading.Thread(target=lambda: results.append(discover('deb', probe, lambda _: progress.set())))
    worker.start()
    try:
        assert progress.wait(2), 'A slow repository must not hold back other discovered choices'
        assert not results
    finally:
        slow.set()
        worker.join(5)
    assert results[0].versions == ('1.25', '1.24')


@pytest.mark.parametrize('family', ['rpm', 'deb'])
@pytest.mark.parametrize('workload', ['kubernetes-node', 'kubernetes-client'])
def test_patch_scan_snapshots_tk_state_and_retains_full_builds(monkeypatch, family, workload):
    host = KubernetesWorkloadMixin()
    interp = tk.Tcl()
    host.release_var = tk.StringVar(interp, '24.04' if family == 'deb' else '9')
    host.arch_var = tk.StringVar(interp, 'amd64' if family == 'deb' else 'x86_64')
    host.k8s_minor_var = tk.StringVar(interp, '1.33')
    host.k8s_patch_status_var = tk.StringVar(interp)
    host.package_version_var = tk.StringVar(interp, 'Latest')
    host.package_version_combo = {}
    host._profile = lambda: SimpleNamespace(key='fixture', package_family=family)
    host._workload = lambda: load_workloads()[workload]
    repo = core.RepoSpec('Kubernetes', 'https://fixture.invalid/', role='kubernetes')
    host.repo_rows = [repo]
    host._version_scan_repositories = lambda _: ([repo], 'kubernetes')
    host.events = Queue()
    backend = apt_core if family == 'deb' else core
    packages = []
    for name in ['kubelet', 'kubeadm', 'kubectl']:
        for patch in ['4', '5']:
            if name == 'kubeadm' and patch == '5':
                continue
            if family == 'deb':
                package = apt_core.DebPackage(name, 'amd64', f'1.33.{patch}-1.1', 'file.deb', 'sha256', '', repo)
            else:
                package = core.Package(name=name, arch='x86_64', epoch='0', version=f'1.33.{patch}',
                    release='150500.1.1', location='file.rpm', checksum_type='sha256', checksum='', repo=repo)
            packages.append(package)
    entered, finish = threading.Event(), threading.Event()
    def load(snapshot, arches, reporter):
        assert snapshot is not repo
        assert snapshot.url == 'https://fixture.invalid/'
        entered.set()
        assert finish.wait(3)
        return packages
    monkeypatch.setattr(backend, 'load_repository', load)
    host._scan_k8s_patch_versions()
    assert entered.wait(2)
    # Mutating UI state and the source after dispatch cannot affect the worker.
    host.arch_var.set('arm64'); repo.url = 'https://changed.invalid/'
    finish.set()
    kind, context, versions, error = host.events.get(timeout=5)
    assert kind == 'k8s_patch_versions' and not error
    assert len(versions) == (1 if workload == 'kubernetes-node' else 2)
    assert all('-' in v and '1.33.' in v for v in versions)
    host._receive_k8s_patch_versions(context, versions, error)
    assert 'values' not in host.package_version_combo, 'A stale scan must not update the current target'


def test_generic_package_scan_result_cannot_replace_another_workload():
    host = DiscoveryMixin()
    host._package_version_scan_context = lambda: ('new workload',)
    host.package_version_combo = {}
    host.package_version_var = Mock()
    host._receive_package_versions(('old workload',), ['Latest', '9.1'])
    assert host.package_version_combo == {}
    assert not host.package_version_var.set.called
