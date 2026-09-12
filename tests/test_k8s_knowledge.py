"""Upstream facts may refresh; failed refreshes cannot rewrite operator intent."""
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import k8s_knowledge as k
from k8s_discovery import discover
from k8s_version import api_minor
from k8s_policy import evaluate
from kubernetes_workflow import WorkloadContext, report, check_acknowledgement
from tests import test_application_startup as startup

application = startup.application
isolated_state = startup.isolated_state
requires_display = startup.requires_display

SCHEDULE = b'schedules:\n- release: "1.90"\n  releaseDate: "2025-01-01"\n  endOfLifeDate: "2099-01-01"\n- release: "1.91"\n  releaseDate: "2099-01-01"\n  endOfLifeDate: "2100-01-01"\n'
HISTORY = b'branches:\n- release: "1.19"\n  endOfLifeDate: "2021-10-28"\n'
POLICY = b'# Version skew policy\nFixture prose is never executed as code.\n'


def getter(url):
    return SCHEDULE if url == k.SCHEDULE else HISTORY if url == k.HISTORY else POLICY


def knowledge():
    now = datetime.now(timezone.utc).isoformat()
    return k.Knowledge((k.Release('1.33','2099-01-01'),), tuple(
        k.Evidence(url, hashlib.sha256(getter(url)).hexdigest(), now) for url in k.URLS))


def test_upstream_releases_extend_beyond_former_ceiling_and_skip_future_dates(tmp_path):
    result = k.refresh(tmp_path/'cache.json', knowledge(), getter=getter, force=True)
    assert not result.error
    assert [r.minor for r in result.releases] == ['1.90', '1.33', '1.19']
    assert result.repository_candidates == ('1.90', '1.33')
    assert k.read(tmp_path/'cache.json') == result


def test_known_repository_candidates_survive_missing_older_repositories():
    urls = []
    observation = discover('deb', lambda url: urls.append(url) or '/v1.90/' in url,
                           candidates=('1.24','1.25','1.26','1.90'))
    assert observation.versions == ('1.90',) and len(urls) == 4


@pytest.mark.parametrize('value,minor', [('1.19',19),('19',19),('1.61',61),('133',133),('1.0',0)])
def test_api_input_is_not_a_support_window(value, minor):
    assert api_minor(value) == minor


@pytest.mark.parametrize('value', ['abc','-1','1.33 garbage','2.0','1.33-rc.1'])
def test_invalid_api_syntax_still_rejected(value):
    with pytest.raises(ValueError): api_minor(value)


@pytest.mark.parametrize('bad', [b'<html>error</html>', b'schedules: []', b'schedules: 1',
    b'schedules: [&row {release: "1.90"}, *row]', b'schedules:\n- release: "1.90"\n  endOfLifeDate: nope',
    b'x' * (k.MAX_BYTES + 1)], ids=['html-error', 'empty-list', 'wrong-shape', 'yaml-alias', 'invalid-date', 'oversized'])
def test_bad_feed_preserves_last_release_facts_and_timestamps(tmp_path, bad):
    previous = knowledge()
    result = k.refresh(tmp_path/'cache.json', previous,
        getter=lambda url: bad if url == k.SCHEDULE else getter(url), force=True)
    assert result.error and result.releases == previous.releases
    before = {s.url:s for s in previous.sources}
    assert next(s for s in result.sources if s.url == k.SCHEDULE) == before[k.SCHEDULE]


def test_outage_keeps_good_cache_byte_for_byte_then_recovers(tmp_path):
    path=tmp_path/'cache.json'; previous=knowledge();k.save(path,previous)
    original=path.read_bytes()
    def outage(_): raise TimeoutError('offline')
    failed=k.refresh(path,previous,getter=outage,force=True)
    assert failed.error and failed.releases == previous.releases and path.read_bytes() == original
    healed=k.refresh(path,failed,getter=getter)
    assert not healed.error and healed.releases[0].minor == '1.90'
    assert k.read(path) == healed


@pytest.mark.parametrize('broken', ['{', '{"schema":99}', '[]'])
def test_corrupt_cache_is_replaced_only_after_valid_refresh(tmp_path, broken):
    path=tmp_path/'cache.json';path.write_text(broken)
    assert k.read(path) is None
    result=k.refresh(path,getter=getter,force=True)
    assert result.releases and not result.error and k.read(path) == result


def test_fresh_cache_skips_network(tmp_path):
    get=Mock(side_effect=AssertionError('unexpected request'))
    previous=knowledge()
    assert k.refresh(tmp_path/'cache.json', previous, getter=get) == previous
    assert not get.called


def test_policy_change_is_sticky_and_never_applied_as_rules(tmp_path):
    previous=knowledge()
    result=k.refresh(tmp_path/'cache.json',previous,
        getter=lambda url: POLICY+b'New rule text\n' if url == k.KUBEADM else getter(url),force=True)
    assert result.changed_policies == (k.KUBEADM,)
    context=WorkloadContext(workload='kubernetes-client',minor='1.90',knowledge=result)
    data=report(context,[])
    assert any('documentation changed' in f['message'] for f in data['findings'])
    assert all(f['severity']=='advisory' for f in data['findings'])
    check_acknowledgement(data)
    assert k.read(tmp_path/'cache.json').changed_policies == (k.KUBEADM,)
    again=k.refresh(tmp_path/'cache.json',result,
        getter=lambda url: POLICY+b'New rule text\n' if url == k.KUBEADM else getter(url),force=True)
    assert again.changed_policies == (k.KUBEADM,)


def test_unknown_and_historical_versions_have_notices_not_rejection():
    info=replace(knowledge(), releases=(k.Release('1.19','2021-10-28'),))
    messages=k.notices(info,('1.19','1.133'),today=date(2026,9,11))
    assert any('end of life' in s for s in messages)
    assert any('absent' in s and 'usable' in s for s in messages)
    WorkloadContext(workload='kubernetes-client',minor='1.19',oldest='19',newest='19').validate()


@pytest.mark.parametrize('minor,api', [(30,33),(35,33),(34,33)])
def test_lifecycle_inference_is_advisory_without_operation_context(minor,api):
    rows=evaluate([SimpleNamespace(name='kubeadm',version=f'1.{minor}.0')],minor,api,api)
    assert rows and all(f.severity=='advisory' for f in rows)


def test_future_dated_or_foreign_cache_is_rejected(tmp_path):
    path=tmp_path/'cache.json';k.save(path,knowledge());data=json.loads(path.read_text())
    data['sources'][0]['url']='https://untrusted.invalid/data'
    path.write_text(json.dumps(data));assert k.read(path) is None
    k.save(path,knowledge());data=json.loads(path.read_text())
    data['sources'][0]['observed_at']=(datetime.now(timezone.utc)+timedelta(days=5)).isoformat()
    path.write_text(json.dumps(data));assert k.read(path) is None


@requires_display
def test_gui_refresh_keeps_minor_and_full_package_pin(application,monkeypatch):
    from kubernetes_workflow import LABELS
    monkeypatch.setattr(application,'_discover_kubernetes_minors',lambda:None)
    monkeypatch.setattr(application,'_scan_k8s_patch_versions',lambda:None)
    application.workload_var.set(LABELS['kubernetes-client']);application._workload_changed()
    application.k8s_minor_var.set('1.33');application.package_version_var.set('1.33.4-1.1')
    application._receive_k8s_knowledge(knowledge())
    assert application.k8s_minor_var.get() == '1.33'
    assert application.package_version_var.get() == '1.33.4-1.1'
    application.apiserver_oldest_minor_var.set('19')
    assert 'absent' in application.k8s_knowledge_var.get()


@requires_display
def test_gui_schedules_bounded_retry_and_pauses_it_during_build(application,monkeypatch):
    from kubernetes_workflow import LABELS
    calls=[]
    monkeypatch.setattr(application,'after',lambda delay,callback:calls.append((delay,callback)) or 'timer')
    monkeypatch.setattr(application,'after_cancel',Mock())
    for _ in range(4): application._schedule_k8s_refresh(True)
    assert [c[0] for c in calls] == [60000,300000,900000,900000]
    application._schedule_k8s_refresh(False)
    assert calls[-1][0] == k.TTL_SECONDS*1000
    application.workload_var.set(LABELS['kubernetes-client'])
    monkeypatch.setattr(application,'_busy',lambda:True)
    refresh=Mock();monkeypatch.setattr(application,'_discover_kubernetes_minors',refresh)
    application._retry_k8s_refresh();assert not refresh.called
    monkeypatch.setattr(application,'_busy',lambda:False)
    application._retry_k8s_refresh();refresh.assert_called_once_with(force=True)
