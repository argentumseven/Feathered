"""Dependency injection is per-host; the old app facade is only a narrow adapter."""
from datetime import datetime
from types import SimpleNamespace

import app
from feathered_app.build_output import BuildOutputMixin
from feathered_app.dependency_ports import (ApplicationDependencyPorts,
                                            legacy_facade_ports, ports_for)
from feathered_app.application.tools import ToolsMixin


class Var:
    def __init__(self, value=""):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


def _output_host(dependencies=None):
    host = SimpleNamespace(
        _profile=lambda: SimpleNamespace(key="arch"),
        _mirror_mode=lambda: False,
        _single_mode=lambda: False,
        _workload=lambda: SimpleNamespace(key="nginx"),
        release_var=Var("rolling"), arch_var=Var("x86_64"),
        folder_scheme_var=Var("Custom label"), folder_label_var=Var("nginx"),
        folder_stamp_var=Var("date"),
    )
    if dependencies is not None:
        host._app_dependencies = dependencies
    return host


def _summary_host(dependencies=None):
    host = SimpleNamespace(
        _pick_mode=lambda: False, _mirror_mode=lambda: False,
        _single_mode=lambda: False,
        last_result=SimpleNamespace(selected=[SimpleNamespace(nevra="nginx", size=2048)]),
        download_size_var=Var(),
    )
    if dependencies is not None:
        host._app_dependencies = dependencies
    return host


def test_two_hosts_have_independent_formatters_and_clock():
    class OldClock:
        @staticmethod
        def now():
            return datetime(2041, 1, 2, 3, 4, 5)

    class NewClock:
        @staticmethod
        def now():
            return datetime(2042, 8, 9, 3, 4, 5)

    old = ApplicationDependencyPorts(datetime=OldClock, human_size=lambda size: f"old:{size}")
    new = ApplicationDependencyPorts(datetime=NewClock, human_size=lambda size: f"new:{size}")
    assert BuildOutputMixin._folder_name(_output_host(old)) == "2041-01-02_nginx"
    assert BuildOutputMixin._folder_name(_output_host(new)) == "2042-08-09_nginx"

    first = _summary_host(old)
    second = _summary_host(new)
    ToolsMixin._refresh_download_size_preview(first)
    ToolsMixin._refresh_download_size_preview(second)
    assert "old:2048" in first.download_size_var.value
    assert "new:2048" in second.download_size_var.value
    assert ports_for(first) is old and ports_for(second) is new


def test_partial_tk_host_dependency_resolution_does_not_enter_tk_getattr():
    partial = object.__new__(app.App)
    assert ports_for(partial) is legacy_facade_ports
    injected = ApplicationDependencyPorts(human_size=lambda size: "isolated")
    partial._app_dependencies = injected
    assert ports_for(partial) is injected


def test_facade_overrides_are_narrow_and_do_not_mutate_component_globals(monkeypatch):
    from feathered_app.application import provenance, tools
    from feathered_app import build_output

    original_size = tools.human_size
    original_clock = build_output.datetime
    original_relationship = provenance.evidence_relationship
    original_distinct = provenance.mirrors_are_distinct
    with monkeypatch.context() as patch:
        patch.setattr(app, "human_size", lambda n: f"facade:{n}")
        patch.setattr(app, "datetime", type("Clock", (), {"now": lambda: datetime(2045, 5, 6)}))
        patch.setattr(app, "evidence_relationship", lambda *_: "injected-relationship")
        patch.setattr(app, "mirrors_are_distinct", lambda *_: (True, "injected"))
        assert tools.human_size is original_size
        assert build_output.datetime is original_clock
        assert provenance.evidence_relationship is original_relationship
        assert provenance.mirrors_are_distinct is original_distinct
        assert "facade:2048" in _summary_and_read(_summary_host())
        assert BuildOutputMixin._folder_name(_output_host()) == "2045-05-06_nginx"
        assert ports_for(SimpleNamespace()).evidence_relationship(None, "url") == "injected-relationship"
        # An explicitly injected host is never overridden through the facade.
        isolated = _summary_host(ApplicationDependencyPorts(human_size=lambda n: "per-instance"))
        assert "per-instance" in _summary_and_read(isolated)
    assert legacy_facade_ports.human_size is app.human_size
    assert legacy_facade_ports.datetime is app.datetime


def _summary_and_read(host):
    ToolsMixin._refresh_download_size_preview(host)
    return host.download_size_var.value


def test_headless_host_owns_its_ports_and_uses_injected_naming_clock(monkeypatch):
    from build_spec import BuildSpec
    from core import Reporter
    from feathered_app.build_services import BuildServices
    from feathered_app.headless_host import HeadlessHost

    class FrozenClock:
        @staticmethod
        def now():
            return datetime(2043, 11, 12, 13, 14, 15)

    injected = ApplicationDependencyPorts(datetime=FrozenClock)
    host = HeadlessHost(BuildSpec(), BuildServices(Reporter()),
                        workloads={}, dependencies=injected)
    other = HeadlessHost(BuildSpec(), BuildServices(Reporter()), workloads={})
    assert host._build_naming_time == datetime(2043, 11, 12, 13, 14, 15)
    assert ports_for(host) is injected
    assert ports_for(other) is not injected
    assert ports_for(other) is not legacy_facade_ports
    with monkeypatch.context() as patch:
        patch.setattr(app, 'human_size', lambda size: 'GUI override')
        assert ports_for(host).human_size(2048) == '2.0 KB'
        assert ports_for(other).human_size(2048) == '2.0 KB'
