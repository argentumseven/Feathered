"""Live DNF evidence collector has a pure, testable catalog-selection path."""
from types import SimpleNamespace

import native_rpm_live_probe as live
from source_model import RootSourcePolicy, SourcePlan
from workloads import load_workloads


def test_native_probe_mirrors_required_optional_and_candidate_selection():
    plan = SourcePlan([
        RootSourcePolicy('necessary', 'distribution', candidates=('first', 'second')),
        RootSourcePolicy('extra', 'distribution', optional=True),
        RootSourcePolicy('must', 'distribution'),
    ])
    roots, missing, skipped = live.select_roots(plan, {'second'})
    assert roots == ['second']
    assert missing == ['must']
    assert skipped == ['extra']


def test_native_probe_refuses_to_treat_vendor_roots_as_distribution():
    plan = SourcePlan([RootSourcePolicy('docker-ce', 'workload', role='docker')])
    try:
        live.select_roots(plan, {'docker-ce'})
    except ValueError as exc:
        assert 'vendor repository' in str(exc)
    else:
        raise AssertionError('vendor package was silently tested against base repositories')


def test_fedora_diagnostic_presets_are_derived_from_live_workload_catalog():
    catalog = load_workloads()
    for key in ('cockpit', 'kernel-dev', 'storage-tools'):
        plan = catalog[key].source_plan('rpm')
        assert plan.roots
        assert all(root.source_kind == 'distribution' for root in plan.roots)


def test_native_probe_never_executes_a_package_install(tmp_path, monkeypatch):
    commands = []

    def fake_run(argv):
        commands.append(argv)
        if 'repoquery' in argv:
            return SimpleNamespace(returncode=0, stdout='cockpit\ncockpit-system\n', stderr='')
        return SimpleNamespace(returncode=0, stdout='stored', stderr='')

    monkeypatch.setattr(live, '_run', fake_run)
    result = live.probe('fedora', '44', ['cockpit'], tmp_path)
    assert result['presets']['cockpit']['status'] == 'dnf-accepted'
    assert commands[-1][-1] == 'cockpit-system'
    assert any(arg.startswith('--store=') for arg in commands[-1])
    assert any(arg.startswith('--installroot=') for arg in commands[-1])
    assert (tmp_path / 'report.json').is_file()
