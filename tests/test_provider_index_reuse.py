"""Pass-local index reuse must preserve RPM root choice and provenance constraints."""
import json
from pathlib import Path

import pytest
import core

SCENARIOS = ('ordinary', 'constrained', 'mixed', 'unsatisfiable', 'source-pinned', 'virtual', 'python-alias', 'empty-filter')
GOLDEN = Path(__file__).parent / 'fixtures/provider_resolution.json'


def inputs(scenario):
    repo = core.RepoSpec('Base', 'https://fixture.invalid/base/')
    repo.source_tier = 'base'
    other = core.RepoSpec('Supplemental', 'https://fixture.invalid/extra/')
    other.source_tier = 'additional'
    def pkg(name, version, source=repo, provides=()):
        return core.Package(name, 'x86_64', '0', version, '1', name+'.rpm', 'sha256', '', source,
                            provides=list(provides))
    packages = [pkg(name, version) for name in ('alpha', 'beta') for version in ('1', '2')]
    requests = [(name, None, None) for name in ('alpha', 'beta')]
    constraints = {name: [core.Requirement(name, 'EQ', '0', '1', '1')] for name in ('alpha', 'beta')}
    if scenario == 'ordinary':
        constraints = {}
    elif scenario == 'mixed':
        constraints.pop('beta')
    elif scenario == 'unsatisfiable':
        constraints['alpha'] = [core.Requirement('alpha', 'GT', '0', '9', '1')]
    elif scenario == 'empty-filter':
        constraints = {name: [core.Requirement(name, 'GT', '0', '9', '1')] for name in constraints}
    elif scenario == 'source-pinned':
        packages += [pkg(name, '99', other) for name in ('alpha', 'beta')]
        requests = [(name, None, None, None, 'x86_64', 'distribution', repo.source_identity)
                    for name in ('alpha', 'beta')]
    elif scenario == 'virtual':
        for p in packages:
            p.provides.append(core.Requirement(p.name+'-api', 'EQ', '0', p.version, p.release))
        requests = [(name+'-api', None, None) for name in ('alpha', 'beta')]
    elif scenario == 'python-alias':
        packages += [pkg('python3', version, provides=[core.Requirement('python(abi)', 'EQ', '0', version)])
                     for version in ('3.9', '3.11')]
        constraints['python3'] = [core.Requirement('python3', 'EQ', '0', '3.9', '1')]
        for p in packages[:4]:
            p.provides.append(core.Requirement(f'python3.{"9" if p.version == "1" else "11"}dist({p.name})'))
        requests = [(f'python3dist({name})', None, None) for name in ('alpha', 'beta')]
    return packages, requests, constraints


def snapshot(scenario):
    packages, requests, constraints = inputs(scenario)
    events = []
    result, discovered = core._resolve_pass(requests, packages, 'x86_64', core.BuildOptions(),
                                            core.Reporter(log=events.append), constraints)
    def identity(p):
        return [p.nevra, p.repo.source_identity]
    return {
        'selected': [identity(p) for p in result.selected],
        'roots': [identity(p) for p in result.roots],
        'unresolved': [core.format_requirement(r) for r in result.unresolved],
        'conflicts': result.conflicts, 'reasons': result.reasons,
        'unresolved_notes': result.unresolved_notes,
        'skipped_installed': result.skipped_installed,
        'installed_satisfied': result.installed_satisfied,
        'discovered': [[name, core.format_requirement(req)] for name, req in discovered],
        'choices': getattr(result, 'provider_choices', []),
        # Only repeated index diagnostics change when an actual rebuild is avoided.
        'events': [event for event in events if not event.startswith('Detected default Python ABI')],
    }


@pytest.mark.parametrize('scenario', SCENARIOS)
def test_provider_selection_matches_pre_optimization(scenario):
    assert snapshot(scenario) == json.loads(GOLDEN.read_text())[scenario]


@pytest.mark.parametrize('scenario, expected', [('ordinary', 1), ('mixed', 2), ('constrained', 2), ('python-alias', 2), ('empty-filter', 2)])
def test_at_most_one_constrained_index_per_pass(monkeypatch, scenario, expected):
    original = core.build_provider_index
    calls = []
    def counted(packages, reporter=None):
        calls.append(len(packages))
        return original(packages, reporter)
    monkeypatch.setattr(core, 'build_provider_index', counted)
    snapshot(scenario)
    assert len(calls) == expected


def test_new_pass_rebuilds_for_new_constraints_and_metadata():
    packages, requests, constraints = inputs('constrained')
    options = core.BuildOptions()
    first, _ = core._resolve_pass(requests, packages, 'x86_64', options, core.Reporter(), constraints)
    assert [p.version for p in first.roots] == ['1', '1']
    for name in constraints:
        constraints[name] = [core.Requirement(name, 'EQ', '0', '2', '1')]
    second, _ = core._resolve_pass(requests, packages, 'x86_64', options, core.Reporter(), constraints)
    assert [p.version for p in second.roots] == ['2', '2']
    packages[1].version = '3'
    third, _ = core._resolve_pass(requests, packages, 'x86_64', options, core.Reporter(), {})
    assert [p.version for p in third.roots] == ['3', '2']


def test_cancelled_pass_does_not_retain_filtered_candidates():
    packages, requests, constraints = inputs('constrained')
    def cancel(message):
        if message.startswith('Root:'):
            raise core.Cancelled()
    with pytest.raises(core.Cancelled):
        core._resolve_pass(requests, packages, 'x86_64', core.BuildOptions(), core.Reporter(log=cancel), constraints)
    result, _ = core._resolve_pass(requests, packages, 'x86_64', core.BuildOptions(), core.Reporter(), {})
    assert [p.version for p in result.roots] == ['2', '2']
