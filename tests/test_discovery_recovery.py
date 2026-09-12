"""Partial outages and stale completions must retain authoritative observations."""
from pathlib import Path
from dataclasses import replace
import pytest
import k8s_discovery as d
import k8s_knowledge as k
from tests.test_k8s_knowledge import getter, knowledge, POLICY

def test_partial_outage_is_not_a_successful_smaller_snapshot():
    def probe(url):
        if 'v1.34' in url: raise TimeoutError('offline')
        return True
    current=d.discover('deb',probe,candidates=('1.34','1.33'))
    assert current.error

@pytest.mark.parametrize('code,status',[(404,'absent'),(410,'absent'),(429,'indeterminate'),(503,'indeterminate'),(403,'indeterminate')])
def test_probe_distinguishes_authoritative_absence(code,status):
    from urllib.error import HTTPError
    def opener(request,**kw):raise HTTPError(request.full_url,code,'fixture',{},None)
    assert d.probe_repository('https://pkgs.k8s.io/fixture',opener).status==status

def test_partial_merge_keeps_old_time_and_new_successes_and_removes_proven_absence(tmp_path):
    previous=d.Observation(('1.34','1.32'),'2025-01-01T00:00:00+00:00','fixture')
    def probe(url):
        if 'v1.34' in url:return d.ProbeResult('indeterminate','timeout')
        if 'v1.32' in url:return d.ProbeResult('absent','HTTP 404')
        return d.ProbeResult('available')
    current=d.discover('deb',probe,candidates=('1.35','1.34','1.32'))
    merged=d.retain(previous,current)
    assert merged.versions==('1.35','1.34') and merged.observed_at==previous.observed_at
    assert merged.error and dict(merged.checks)['1.34'].status=='indeterminate'
    path=tmp_path/'cache.json';d.save(path,merged)
    assert d.read(path)==merged


def test_stale_refresh_cannot_clear_policy_change(tmp_path):
    previous=knowledge();path=tmp_path/'knowledge.json'
    newer=k.refresh(path,previous,getter=lambda u:POLICY+b'changed' if u==k.KUBEADM else getter(u),force=True)
    assert newer.changed_policies
    older=k.refresh(path,previous,getter=getter,force=True)
    assert k.KUBEADM in older.changed_policies
    assert k.KUBEADM in k.read(path).changed_policies


def test_persistent_writer_lease_retains_cache_without_network(tmp_path):
    path=tmp_path/'knowledge.json'; previous=knowledge();k.save(path,previous)
    from unittest.mock import Mock
    fetch=Mock(side_effect=AssertionError('must not fetch behind another owner'))
    with k._cache_lease(path):
        result=k.refresh(path,previous,getter=fetch,force=True)
    assert result.releases==previous.releases and result.error
    assert not fetch.called and k.read(path)==previous


def test_concurrent_refreshes_reconcile_the_committed_policy_signal(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    entered=Event();release=Event();path=tmp_path/'knowledge.json';previous=knowledge()
    def first(url):
        entered.set();assert release.wait(5)
        return POLICY+b'new policy' if url==k.KUBEADM else getter(url)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first_job=pool.submit(k.refresh,path,previous,getter=first,force=True)
        assert entered.wait(5)
        second_job=pool.submit(k.refresh,path,previous,getter=getter,force=True)
        release.set()
        assert k.KUBEADM in first_job.result(timeout=5).changed_policies
        assert k.KUBEADM in second_job.result(timeout=5).changed_policies
    assert k.KUBEADM in k.read(path).changed_policies


def test_family_switch_shares_one_knowledge_refresh(tmp_path,monkeypatch):
    from queue import Queue
    from types import SimpleNamespace
    from unittest.mock import Mock
    from feathered_app.ui.kubernetes import KubernetesWorkloadMixin
    from feathered_app.ui import kubernetes as ui
    workers=[]
    jobs=SimpleNamespace(submit=lambda key,work:workers.append(work))
    monkeypatch.setattr(k,'refresh',lambda *args,**kw:knowledge())
    class Host(KubernetesWorkloadMixin):
        family='rpm'
        events=Queue()
        k8s_observation_var=Mock()
        def _profile(self):return SimpleNamespace(package_family=self.family)
        def _release_cache_path(self):return tmp_path/'releases.json'
        def _query_jobs(self):return jobs
        _receive_k8s_knowledge=Mock()
        _start_k8s_repository_discovery=Mock()
    host=Host();host._discover_kubernetes_minors()
    host.family='deb';host._discover_kubernetes_minors()
    assert len(workers)==1
    from threading import Event
    kind,generation,result=workers[0](Event())
    assert kind=='k8s_knowledge_finished'
    host._finish_k8s_knowledge_refresh(generation-1,result)
    assert host._k8s_knowledge_refresh_running
    host._finish_k8s_knowledge_refresh(generation,result)
    assert not host._k8s_knowledge_refresh_running
    assert {call.args[0] for call in host._start_k8s_repository_discovery.call_args_list}=={'rpm','deb'}
