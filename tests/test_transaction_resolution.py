"""Convergence and failure regressions through the production transaction adapter."""
from threading import Event

import pytest

import apt_core
import core
import transaction_model as transaction


def package(name='app', version='1', source='base'):
    repo = core.RepoSpec(source, f'https://example.test/{source}', repo_format='apt')
    return apt_core.DebPackage(name, 'amd64', version, name + '.deb', 'sha256', '', repo)


class ScriptedResolver:
    def __init__(self, selections):
        self.selections = selections
        self.calls = []
        self.results = []

    def __call__(self, requests, packages, architecture, options, reporter):
        self.calls.append((list(requests), packages, architecture, options, reporter))
        result = apt_core.DebResolutionResult(
            selected=list(self.selections[len(self.calls) - 1]), unresolved=[], roots=[])
        self.results.append(result)
        return result


def run(resolver, packages, *, options=None, requests=None, reporter=None):
    return transaction.resolve_transaction(
        resolver, [('app', None, None)] if requests is None else requests,
        packages, 'amd64', options if options is not None else core.BuildOptions(),
        reporter if reporter is not None else core.Reporter(), 'deb')


def test_stability_returns_original_result_and_preserves_caller_options():
    app = package()
    inventory = apt_core.AptTargetInventory(packages={('app', 'amd64'): '0'})
    options = core.BuildOptions(target_inventory=inventory)
    resolver = ScriptedResolver([[app], [app]])
    reporter = core.Reporter()
    rows = [app]
    result = run(resolver, rows, options=options, reporter=reporter)
    assert result is resolver.results[1]
    assert all(call[1] is rows and call[2] == 'amd64' and call[4] is reporter for call in resolver.calls)
    first, second = [call[3] for call in resolver.calls]
    assert first is not options and second is not options and first is not second
    assert first._transaction_candidates == [] and second._transaction_candidates == [app]
    assert first.target_inventory.packages == {('app', 'amd64'): '0'}
    assert second.target_inventory.packages == {}
    assert inventory.packages == {('app', 'amd64'): '0'}
    assert not hasattr(options, '_transaction_candidates')
    assert result.target_inventory is inventory
    assert result.transaction_family == 'deb'
    assert result.validation_scope == 'forward-closure' and not result.arch_full_upgrade
    assert result.root_contract == [transaction.RootRequest('app')]
    assert not hasattr(resolver.results[0], 'root_contract')


def test_package_order_does_not_prevent_stability():
    first, second = package(), package('dependency')
    resolver = ScriptedResolver([[first, second], [second, first]])
    result = run(resolver, [first, second])
    assert result.selected == [second, first] and len(resolver.calls) == 2


@pytest.mark.parametrize('different_source', [False, True])
def test_cycle_in_package_or_source_identity_fails_without_finalizing(different_source):
    first = package()
    second = package(version='1' if different_source else '2', source='other' if different_source else 'base')
    resolver = ScriptedResolver([[first], [second], [first]])
    with pytest.raises(RuntimeError, match='Target transaction did not converge'):
        run(resolver, [first, second])
    assert len(resolver.calls) == 3
    assert all(not hasattr(result, 'root_contract') for result in resolver.results)


@pytest.mark.parametrize('budget,expected', [(0, 4), (2, 4), (5, 7)])
def test_nonrepeating_unstable_state_exhausts_the_existing_budget(budget, expected):
    rows = [package(version=str(i)) for i in range(expected)]
    resolver = ScriptedResolver([[row] for row in rows])
    with pytest.raises(RuntimeError, match='Final target-state validation exceeded the resolution budget'):
        run(resolver, rows, options=core.BuildOptions(max_resolution_passes=budget))
    assert len(resolver.calls) == expected
    assert not hasattr(resolver.results[-1], 'root_contract')


def test_cancel_before_inventory_preparation_or_resolver(monkeypatch):
    def forbidden(*args):
        pytest.fail('Cancellation must precede inventory preparation and resolution')

    monkeypatch.setattr(transaction, 'retained_inventory', forbidden)
    event = Event()
    event.set()
    with pytest.raises(core.Cancelled):
        run(forbidden, [], reporter=core.Reporter(cancel_event=event))


def test_cancel_after_one_pass_cannot_publish_partial_result():
    app = package()
    resolver = ScriptedResolver([[app]])
    event = Event()

    def once(*args):
        result = resolver(*args)
        event.set()
        return result

    with pytest.raises(core.Cancelled):
        run(once, [app], reporter=core.Reporter(cancel_event=event))
    assert len(resolver.calls) == 1 and not hasattr(resolver.results[0], 'root_contract')


def test_backend_exception_propagates_without_reverse_validation(monkeypatch):
    failure = core.Cancelled('backend interrupted')

    def once(*args):
        raise failure

    def forbidden(*args):
        pytest.fail('Failed pass must not reach reverse validation')

    monkeypatch.setattr(transaction, 'retained_failures', forbidden)
    with pytest.raises(core.Cancelled) as caught:
        run(once, [])
    assert caught.value is failure


def test_repair_extends_owned_roots_and_restarts_with_empty_prior(monkeypatch):
    app, old, new = package(), package('owner'), package('owner', '2')
    requirement = object()
    resolver = ScriptedResolver([[app], [app], [app, new], [app, new]])
    problems = iter([[(old, requirement, 'dependency')], []])
    monkeypatch.setattr(transaction, 'retained_failures', lambda *args: next(problems))
    original = [('app', None, None)]
    result = run(resolver, [app, new], requests=original)
    assert original == [('app', None, None)]
    assert [[r.name for r in call[0]] for call in resolver.calls] == [
        ['app'], ['app'], ['app', 'owner'], ['app', 'owner']]
    assert resolver.calls[2][3]._transaction_candidates == []
    assert [r.name for r in result.root_contract] == ['app', 'owner']
    assert result.unresolved == []


@pytest.mark.parametrize('already_requested', [False, True])
def test_unrepairable_or_explicit_root_failure_is_retained(monkeypatch, already_requested):
    app, old, new = package(), package('owner'), package('owner', '2')
    requirement = object()
    resolver = ScriptedResolver([[app], [app]])
    monkeypatch.setattr(transaction, 'retained_failures', lambda *args: [(old, requirement, 'lost')])
    roots = [('app', None, None)] + ([('owner', None, None)] if already_requested else [])
    result = run(resolver, [app, new] if already_requested else [app], requests=roots)
    assert result.unresolved == [requirement]
    assert result.unresolved[0] is requirement
    assert result.unresolved_notes == {'lost': f'Retained target package {old.nevra} would lose this requirement'}
    assert len(result.root_contract) == len(roots)


def test_pending_repair_defers_other_failures_until_the_retry(monkeypatch):
    app, old, new, other = package(), package('owner'), package('owner', '2'), package('other')
    first_req, second_req = object(), object()
    resolver = ScriptedResolver([[app], [app], [app, new], [app, new]])
    problems = iter([[(old, first_req, 'first'), (other, second_req, 'second')], [(other, second_req, 'second')]])
    monkeypatch.setattr(transaction, 'retained_failures', lambda *args: next(problems))
    result = run(resolver, [app, new])
    assert resolver.results[1].unresolved == []
    assert result.unresolved == [second_req]


def test_dependencies_disabled_bypasses_reverse_validation(monkeypatch):
    def forbidden(*args):
        pytest.fail('Package-only resolution must not check reverse dependencies')

    monkeypatch.setattr(transaction, 'retained_failures', forbidden)
    resolver = ScriptedResolver([[]])
    result = run(resolver, [], options=core.BuildOptions(include_dependencies=False))
    assert result is resolver.results[0]
    assert result.unresolved == [] and len(resolver.calls) == 1
