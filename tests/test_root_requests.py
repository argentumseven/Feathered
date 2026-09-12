"""Root boundary regressions through both legacy records and public resolvers."""
from dataclasses import FrozenInstanceError, asdict, replace
import pickle

import pytest

import apt_core
import arch_core
import core
import transaction_model
from root_requests import RootRequest, normalize_requests
from test_feather import rpm_pkg
from test_transaction_contract import ap, dp


@pytest.mark.parametrize('length', range(3, 8))
@pytest.mark.parametrize('container', [tuple, list])
def test_legacy_records_preserve_every_field_and_pad_only_missing_fields(length, container):
    fields = ['pkg-name', '2:1.0-3', 'vendor', 'Exact repository', 'amd64', 'distribution', 'source-id']
    value = container(fields[:length])
    roots = normalize_requests([value])
    assert roots[0].as_tuple() == tuple(fields[:length] + [None] * (7 - length))
    assert value == container(fields[:length])


@pytest.mark.parametrize('value', [
    'abc', 'package', b'abc', bytearray(b'abc'), {'name': 'pkg', 'version': '1', 'role': None},
    None, 7, True, [], ['pkg'], ['pkg', None], ['pkg', None, None, None, None, None, None, None],
    iter(['pkg', None, None]),
])
def test_nonrecords_and_wrong_arities_fail_with_a_request_error(value):
    with pytest.raises(RuntimeError, match='Invalid package request'):
        RootRequest.from_value(value)


@pytest.mark.parametrize('position', range(1, 7))
def test_optional_fields_reject_nontext_without_coercion(position):
    fields = ['pkg', None, None, None, None, None, None]
    fields[position] = 42
    with pytest.raises(RuntimeError, match='expected text or None'):
        normalize_requests([fields])
    kwargs = dict(zip(('name', 'version', 'role', 'repository', 'architecture', 'scope', 'source_identity'), fields))
    with pytest.raises(RuntimeError, match='expected text or None'):
        RootRequest(**kwargs)


@pytest.mark.parametrize('name', ['', '-option', 'line\nbreak', 'line\rbreak', 'nul\0name', 7, None])
def test_invalid_names_fail_for_both_records_and_direct_construction(name):
    with pytest.raises(RuntimeError, match='Invalid package root name'):
        RootRequest(name)
    with pytest.raises(RuntimeError, match='Invalid package root name'):
        normalize_requests([(name, None, None)])


def test_typed_roots_retain_identity_order_duplicates_and_empty_optional_fields():
    first = RootRequest('first', '', None, '', '', '', '')
    second = RootRequest('second')
    supplied = [first, second, first]
    normalized = normalize_requests(iter(supplied))
    assert normalized is not supplied and normalized == supplied
    assert normalized[0] is normalized[2] is first
    assert normalized[1] is second
    assert first.as_tuple() == ('first', '', None, '', '', '', '')
    assert list(first) == list(first.as_tuple()) and len(first) == 7
    assert first[0] == 'first' and first[-1] == ''
    assert first[1:4] == ('', None, '') and first[::-1] == first.as_tuple()[::-1]
    with pytest.raises(IndexError):
        _ = first[7]
    with pytest.raises(FrozenInstanceError):
        first.name = 'changed'
    assert replace(first, version='2').version == '2' and first.version == ''


@pytest.mark.parametrize('field', ['version', 'architecture', 'source_identity'])
def test_contradictory_pins_fail_but_unpinned_and_distinct_names_remain_valid(field):
    first = RootRequest('pkg', **{field: 'one'})
    second = RootRequest('pkg', **{field: 'two'})
    with pytest.raises(RuntimeError, match=f'Contradictory {field}'):
        normalize_requests([first, RootRequest('other'), second])
    assert normalize_requests([RootRequest('pkg'), first, first]) == [RootRequest('pkg'), first, first]
    assert normalize_requests([first, RootRequest('other', **{field: 'two'})])


def test_repository_and_role_constraints_are_preserved_without_merging():
    roots = [RootRequest('pkg', role='vendor', repository='one', scope='distribution'),
             RootRequest('pkg', role='dependency', repository='two')]
    assert normalize_requests(roots) == roots


def test_historical_import_and_pickle_paths_remain_usable(monkeypatch):
    assert transaction_model.RootRequest is RootRequest
    assert transaction_model.normalize_requests is normalize_requests
    root = RootRequest('pkg', source_identity='exact')
    with monkeypatch.context() as patch:
        patch.setattr(RootRequest, '__module__', 'transaction_model')
        historical_pickle = pickle.dumps(root)
    restored = pickle.loads(historical_pickle)
    assert restored == root and asdict(restored) == asdict(root)
    assert RootRequest.from_value(restored) is restored


def test_normalization_revalidates_records_restored_without_constructor():
    restored = object.__new__(RootRequest)
    for name, value in asdict(RootRequest('pkg')).items():
        object.__setattr__(restored, name, value)
    object.__setattr__(restored, 'architecture', 17)
    with pytest.raises(RuntimeError, match='architecture: expected text or None'):
        normalize_requests([restored])


@pytest.mark.parametrize('family', ['rpm', 'deb', 'arch'])
def test_public_resolver_rejects_string_record_before_invoking_backend(monkeypatch, family):
    backend = {'rpm': core, 'deb': apt_core, 'arch': arch_core}[family]
    calls = []
    monkeypatch.setattr(backend, '_resolve_once', lambda *args: calls.append(args))
    with pytest.raises(RuntimeError, match='Invalid package request'):
        backend.resolve(['abc'], [], 'amd64' if family == 'deb' else 'x86_64',
                        core.BuildOptions(), core.Reporter())
    assert not calls


@pytest.mark.parametrize('family', ['rpm', 'deb', 'arch'])
def test_public_resolver_preserves_valid_legacy_exact_source_pins(family):
    if family == 'rpm':
        wanted, other = rpm_pkg('pkg', '1'), rpm_pkg('pkg', '2')
        backend, architecture = core, 'x86_64'
    elif family == 'deb':
        wanted, other = dp('pkg', '1'), dp('pkg', '2')
        backend, architecture = apt_core, 'amd64'
    else:
        wanted, other = ap('pkg', '1-1'), ap('pkg', '2-1')
        backend, architecture = arch_core, 'x86_64'
    wanted.repo = core.RepoSpec('wanted', 'https://wanted.example/', repo_format=family)
    other.repo = core.RepoSpec('other', 'https://other.example/', repo_format=family)
    request = [wanted.name, None, None, 'old-display-name', wanted.arch, None, wanted.repo.source_identity]
    result = backend.resolve([request], [other, wanted], architecture,
                             core.BuildOptions(include_dependencies=False), core.Reporter())
    assert not result.unresolved and result.selected == [wanted]
    assert result.root_contract[0].source_identity == wanted.repo.source_identity
    assert result.root_contract[0].repository == 'old-display-name'
