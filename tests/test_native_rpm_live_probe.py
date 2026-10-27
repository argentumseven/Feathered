"""Live DNF evidence collector has a pure, testable catalog-selection path."""
from pathlib import Path
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
            names = ['cockpit', 'cockpit-system', *(f'package-{n}' for n in range(100))]
            return SimpleNamespace(returncode=0, stdout='\n'.join(names) + '\n', stderr='')
        return SimpleNamespace(returncode=0, stdout='stored', stderr='')

    monkeypatch.setattr(live, '_run', fake_run)
    result = live.probe('fedora', '44', ['cockpit'], tmp_path)
    assert result['presets']['cockpit']['status'] == 'dnf-accepted'
    assert commands[0][-1] == '--queryformat=%{name}\\n'
    assert commands[-1][-1] == 'cockpit-system'
    assert '-y' in commands[-1]
    assert any(arg.startswith('--store=') for arg in commands[-1])
    assert any(arg.startswith('--installroot=') for arg in commands[-1])
    assert (tmp_path / 'report.json').is_file()


def test_native_probe_tests_stored_rpms_without_installing(tmp_path, monkeypatch):
    commands = []

    def fake_run(argv):
        commands.append(argv)
        if 'repoquery' in argv:
            names = ['cockpit', 'cockpit-system', *(f'package-{n}' for n in range(100))]
            return SimpleNamespace(returncode=0, stdout='\n'.join(names) + '\n', stderr='')
        if argv[0] == 'dnf5':
            stored = Path(next(arg.removeprefix('--store=') for arg in argv
                               if arg.startswith('--store=')))
            (stored / 'packages').mkdir(parents=True)
            (stored / 'packages' / 'fixture.rpm').touch()
            return SimpleNamespace(returncode=0, stdout='stored', stderr='')
        assert argv[:1] == ['rpm'] and '--test' in argv and '-U' in argv
        assert '--root' in argv and '--nodeps' not in argv
        return SimpleNamespace(returncode=1, stdout='', stderr='unresolved rich requirement')

    monkeypatch.setattr(live, '_run', fake_run)
    result = live.probe('fedora', '44', ['cockpit'], tmp_path, rpm_test=True)
    assert result['presets']['cockpit']['status'] == 'dnf-accepted'
    assert result['presets']['cockpit']['rpm_test_status'] == 'rpm-test-rejected'
    assert len(commands) == 3
    assert (tmp_path / 'cockpit-rpm-test.log').read_text() == 'unresolved rich requirement'
