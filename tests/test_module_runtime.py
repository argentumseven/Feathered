"""Module dependency closure and context selection regressions."""
import json
from copy import deepcopy

import pytest

import core
from module_policy import filter_candidates
from module_runtime import active_module_documents
from test_feather import rpm_pkg


def module(name, stream='stable', context='ctx', requires=None, artifacts=(), version=1):
    data = dict(name=name, stream=stream, context=context, version=version,
                arch='x86_64', artifacts={'rpms': list(artifacts)})
    if requires is not None:
        data['dependencies'] = [{'requires': requires}]
    return {'document': 'modulemd', 'version': 2, 'data': data}


def default(name, stream='stable'):
    return {'document': 'modulemd-defaults', 'version': 1, 'data': {'module': name, 'stream': stream}}


def inventory(states=None, platform=''):
    return core.TargetInventory(metadata={'module_states': json.dumps(states or {}), 'platform_id': platform})


def selected(docs, inv=None):
    return {(row['name'], row['stream'], row['context'])
            for row in active_module_documents(docs, inv, 'x86_64')}


def test_runtime_dependencies_activate_transitively_and_close_cycles():
    docs = [default('app'), module('app', requires={'runtime': ['stable']}),
            module('runtime', requires={'leaf': ['stable']}),
            module('leaf', requires={'app': ['stable']})]
    assert {name for name, _, _ in selected(docs)} == {'app', 'runtime', 'leaf'}


def test_runtime_dependency_survives_package_resolution():
    repo = core.RepoSpec('modules', 'https://fixture.invalid', repo_format='rpm')
    app = rpm_pkg('app', '1', [core.Requirement('runtime')], repo=repo)
    runtime = rpm_pkg('runtime', '1', repo=repo)
    repo.module_documents = [default('app'),
        module('app', requires={'runtime': ['stable']}, artifacts=['app-0:1-1.el9.x86_64']),
        module('runtime', artifacts=['runtime-0:1-1.el9.x86_64'])]
    result = core.resolve([('app', None, None)], [app, runtime], 'x86_64', core.BuildOptions(), core.Reporter())
    assert not result.unresolved
    assert {p.name for p in result.selected} == {'app', 'runtime'}


def test_captured_stream_disambiguates_contexts_and_platform():
    docs = [default('app'), module('app', context='old', requires={'runtime': ['old'], 'platform': ['el8']}),
            module('app', context='new', requires={'runtime': ['new'], 'platform': ['el9']}),
            module('runtime', 'old'), module('runtime', 'new')]
    inv = inventory({'runtime': {'state': 'enabled', 'stream': 'new'}}, 'platform:el9')
    assert selected(docs, inv) == {('app', 'stable', 'new'), ('runtime', 'new', 'ctx')}


@pytest.mark.parametrize('requires', [{'runtime': []}, {'runtime': ['-old']}, {'runtime': ['new']}])
def test_stream_constraint_forms_respect_enabled_state(requires):
    docs = [default('app'), module('app', requires=requires), module('runtime', 'old'), module('runtime', 'new')]
    inv = inventory({'runtime': {'state': 'enabled', 'stream': 'new'}})
    assert ('runtime', 'new', 'ctx') in selected(docs, inv)


def test_alternative_dependency_blocks_are_not_combined():
    app = module('app')
    app['data']['dependencies'] = [{'requires': {'runtime': ['old']}}, {'requires': {'runtime': ['new']}}]
    docs = [default('app'), app, module('runtime', 'new')]
    assert ('runtime', 'new', 'ctx') in selected(docs)


def test_build_dependencies_do_not_enter_runtime_closure():
    app = module('app')
    app['data']['dependencies'] = [{'buildrequires': {'absent-compiler': ['1']}}]
    assert selected([default('app'), app]) == {('app', 'stable', 'ctx')}


@pytest.mark.parametrize('state', [{'state': 'disabled'}, {'state': 'enabled', 'stream': 'other'}])
def test_dependency_cannot_override_disabled_or_enabled_stream(state):
    docs = [default('app'), module('app', requires={'runtime': ['stable']}), module('runtime'), module('runtime', 'other')]
    with pytest.raises(RuntimeError, match='No compatible module'):
        selected(docs, inventory({'runtime': state}))


def test_missing_dependency_and_platform_mismatch_report_reason():
    with pytest.raises(RuntimeError, match='No compatible module'):
        selected([default('app'), module('app', requires={'absent': ['1']})])
    with pytest.raises(RuntimeError, match='platform_id'):
        selected([default('app'), module('app', requires={'platform': ['el8']})], inventory(platform='platform:el9'))


@pytest.mark.parametrize('kind', ['streams', 'contexts'])
def test_unresolved_choices_do_not_depend_on_repository_order(kind):
    if kind == 'streams':
        docs = [default('app'), module('app', requires={'runtime': []}), module('runtime', 'old'), module('runtime', 'new')]
    else:
        docs = [default('app'), module('app', context='old'), module('app', context='new')]
    for rows in (docs, list(reversed(docs))):
        with pytest.raises(RuntimeError, match='Ambiguous module'):
            selected(rows)


def test_duplicate_documents_and_dependency_alternatives_do_not_create_ambiguity():
    app = module('app', requires={'runtime': ['stable']})
    app['data']['dependencies'].append({'requires': {'runtime': []}})
    docs = [default('app'), app, deepcopy(app), module('runtime')]
    assert len(selected(docs)) == 2


def test_newest_context_constraints_retain_older_rpm_artifacts():
    docs = [default('app'), module('app', requires={'missing': ['1']}, version=1), module('app', version=2)]
    rows = active_module_documents(docs, None, 'x86_64')
    assert [row['version'] for row in rows] == [1, 2]


def test_other_architecture_context_does_not_make_selection_ambiguous():
    foreign = module('app', context='arm'); foreign['data']['arch'] = 'aarch64'
    assert selected([default('app'), module('app'), foreign]) == {('app', 'stable', 'ctx')}


def test_filter_masks_nonmodular_providers_even_when_modular_payload_is_absent():
    repo = core.RepoSpec('modules', 'https://fixture.invalid')
    other = rpm_pkg('other', '2', repo=repo)
    other.provides.append(core.Requirement('tool'))
    repo.module_documents = [default('tools'), module('tools', artifacts=['tool-0:1-1.el9.x86_64'])]
    assert filter_candidates([other], None, 'x86_64') == []
    repo.module_documents[1]['data']['demodularized'] = {'rpms': ['tool']}
    assert filter_candidates([other], None, 'x86_64') == [other]


def test_modular_metadata_sources_survive_without_a_selected_rpm(tmp_path):
    repo = core.RepoSpec('modules', 'https://fixture.invalid')
    meta = core.RepoSpec('metadata', 'https://metadata.invalid')
    app = rpm_pkg('app', '1', repo=repo)
    unused = rpm_pkg('unused', '1', repo=meta)
    repo.module_documents = [default('app'), module('app', requires={'runtime': ['stable']}, artifacts=['app-0:1-1.el9.x86_64'])]
    meta.module_documents = [module('runtime')]
    result = core.resolve([('app', None, None)], [app, unused], 'x86_64', core.BuildOptions(), core.Reporter())
    assert [p.name for p in result.selected] == ['app']
    assert {p.repo.name for p in result.module_metadata_packages} == {'modules', 'metadata'}
    import yaml
    for source in (repo, meta):
        source.supplemental_metadata = {'modules': yaml.safe_dump_all(source.module_documents).encode()}
    core.emit_rpm_repository(tmp_path, result.selected, core.Reporter(),
                             supplemental_packages=result.module_metadata_packages)
    local = core.RepoSpec('local', tmp_path.as_uri())
    core.load_repository(local, {'x86_64'}, core.Reporter())
    assert {doc['data'].get('name') for doc in local.module_documents
            if doc['document'] == 'modulemd'} == {'app', 'runtime'}



def test_package_only_acquisition_does_not_require_a_module_context():
    repo = core.RepoSpec('modules', 'https://fixture.invalid')
    package = rpm_pkg('tool', '1', repo=repo)
    repo.module_documents = [default('tools'),
        module('tools', context='first', artifacts=['tool-0:1-1.el9.x86_64']),
        module('tools', context='second', artifacts=['tool-0:1-1.el9.x86_64'])]
    options = core.BuildOptions(include_dependencies=False)
    result = core.resolve([('tool', '1', None)], [package], 'x86_64', options, core.Reporter())
    assert result.selected == [package]
    assert not result.unresolved


@pytest.mark.parametrize('flag,provider_release,required_release,expected', [
    ('EQ', '1', None, True), ('GE', '1', None, True), ('GT', '1', None, False),
    ('LE', '1', None, True), ('LT', '1', None, False),
    ('EQ', None, '1', True), ('GE', None, '1', True), ('GT', None, '1', True),
    ('LE', None, '1', True), ('LT', None, '1', True),
])
def test_rpm_dependency_without_release_uses_version_comparison(flag, expected, provider_release, required_release):
    from rpm_resolution import evr_satisfies
    provide = core.Requirement('runtime', 'EQ', '0', '1.0', provider_release)
    require = core.Requirement('runtime', flag, '0', '1.0', required_release)
    assert evr_satisfies(provide, require) is expected


def test_rpm_explicit_dependency_releases_still_compare():
    from rpm_resolution import evr_satisfies
    provide = core.Requirement('runtime', 'EQ', '0', '1.0', '2')
    require = core.Requirement('runtime', 'EQ', '0', '1.0', '1')
    assert not evr_satisfies(provide, require)
