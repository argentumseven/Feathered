"""The two repository universes must be isolated by construction, not by habit.

Before 1.2.6 the guarantee "mirror repository choices never contaminate a later
workload or exact-package build" was enforced by every site that rebound
``repo_rows`` also remembering to rebind the matching mode slot. A missed
re-synchronisation raised nothing, logged nothing and failed no test; it just
leaked a mirror selection into a transaction build, or discarded a source-plan
edit on the next intent change. All of those sites are in wizard modules that
carry 3-9% automated coverage.

These tests pin the replacement so the guarantee has teeth: mode-scoped storage
where a rebinding cannot desynchronise anything, plus the behaviours existing
callers depend on (in-place mutation, partial-instance safety, the grouped state
view). ``test_no_module_reintroduces_manual_universe_synchronisation`` is the
regression that would have caught the original class of bug.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feathered_app.repository_universe import (
    MIRROR,
    TRANSACTION,
    RepositoryUniverse,
    RepositoryUniverseMixin,
)


class Shell(RepositoryUniverseMixin):
    """Minimal host; the real App adds Tk and fourteen other mixins."""


def test_each_mode_owns_its_own_list():
    shell = Shell()
    shell.transaction_repo_rows = ["base"]
    shell.mirror_repo_rows = ["mirror"]

    assert shell.repo_rows == ["base"]
    shell.activate_repository_universe(MIRROR)
    assert shell.repo_rows == ["mirror"]
    shell.activate_repository_universe(TRANSACTION)
    assert shell.repo_rows == ["base"]


def test_rebinding_repo_rows_cannot_desynchronise_the_active_slot():
    """The exact failure the old aliasing invited: rebind and forget to sync."""
    shell = Shell()
    shell.transaction_repo_rows = ["base"]
    shell.mirror_repo_rows = ["mirror"]
    shell.activate_repository_universe(MIRROR)

    shell.repo_rows = ["replaced"]

    assert shell.mirror_repo_rows == ["replaced"]
    assert shell.transaction_repo_rows == ["base"]
    shell.activate_repository_universe(TRANSACTION)
    assert shell.repo_rows == ["base"]


def test_in_place_mutation_still_reaches_the_stored_list():
    shell = Shell()
    shell.repo_rows = ["base"]
    shell.repo_rows.append("added")
    assert shell.transaction_repo_rows == ["base", "added"]
    assert shell.mirror_repo_rows == []


def test_assigning_one_universe_from_the_other_does_not_alias_them():
    """Copy-on-assign, so the old aliasing cannot be recreated by a caller."""
    shell = Shell()
    shell.transaction_repo_rows = ["base"]
    shell.mirror_repo_rows = shell.transaction_repo_rows

    shell.mirror_repo_rows.append("mirror-only")

    assert shell.transaction_repo_rows == ["base"]
    assert shell.mirror_repo_rows == ["base", "mirror-only"]


def test_activate_reports_whether_the_mode_actually_changed():
    """Callers invalidate analysis state on a real switch only."""
    shell = Shell()
    assert shell.activate_repository_universe(MIRROR) is True
    assert shell.activate_repository_universe(MIRROR) is False
    assert shell.activate_repository_universe(TRANSACTION) is True


def test_transaction_universe_scope_restores_the_caller_mode():
    shell = Shell()
    shell.mirror_repo_rows = ["mirror"]
    shell.activate_repository_universe(MIRROR)

    with shell.transaction_universe():
        shell.repo_rows = ["rebuilt base"]

    assert shell._repository_universe_mode == MIRROR
    assert shell.repo_rows == ["mirror"]
    assert shell.transaction_repo_rows == ["rebuilt base"]


def test_transaction_universe_scope_restores_the_mode_after_an_exception():
    shell = Shell()
    shell.activate_repository_universe(MIRROR)
    with pytest.raises(RuntimeError):
        with shell.transaction_universe():
            raise RuntimeError("source plan rebuild failed")
    assert shell._repository_universe_mode == MIRROR


def test_unknown_mode_is_rejected_rather_than_silently_defaulting():
    universe = RepositoryUniverse()
    with pytest.raises(ValueError):
        universe.activate("mirrror")
    with pytest.raises(ValueError):
        universe.rows("transactions")
    assert universe.mode == TRANSACTION


def test_reads_on_a_partially_constructed_instance_do_not_invent_storage():
    shell = Shell()
    assert shell.repository_rows() == ()
    assert shell.repository_rows(default=None) is None
    assert shell._repository_universe_mode == TRANSACTION
    assert "_repository_universe" not in shell.__dict__

    with pytest.raises(AttributeError):
        shell.repo_rows


def test_delete_clears_only_the_addressed_universe():
    shell = Shell()
    shell.transaction_repo_rows = ["base"]
    shell.mirror_repo_rows = ["mirror"]
    del shell.mirror_repo_rows
    assert shell.mirror_repo_rows == []
    assert shell.transaction_repo_rows == ["base"]


def test_grouped_state_view_still_reaches_the_universe():
    from feathered_app.state import ApplicationStateView

    shell = Shell()
    shell.repo_rows = []
    view = ApplicationStateView(shell).repositories
    view.repo_rows = ["base"]
    assert shell.transaction_repo_rows == ["base"]
    view.repository_universe_mode = MIRROR
    assert shell._repository_universe_mode == MIRROR
    assert view.repo_rows == []


def test_real_app_composes_the_universe_mixin():
    import app

    shell = object.__new__(app.App)
    shell.repo_rows = ["base"]
    shell.mirror_repo_rows = ["mirror"]
    assert shell.repo_rows == ["base"]
    shell.activate_repository_universe(MIRROR)
    assert shell.repo_rows == ["mirror"]


SYNC = re.compile(
    r"self\.(transaction_repo_rows|mirror_repo_rows)\s*=\s*self\.repo_rows\b")


def test_no_module_reintroduces_manual_universe_synchronisation():
    """The bug class, not one instance of it.

    ``self.mirror_repo_rows = self.repo_rows`` is now always either a no-op or a
    mistake. Writing it again signals that someone believes the old aliasing
    contract still holds, so fail before that belief reaches a build.
    """
    offenders = []
    for path in sorted((ROOT / "feathered_app").rglob("*.py")) + [ROOT / "app.py"]:
        if path.name == "repository_universe.py":
            continue  # documents the retired pattern in its module docstring
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if SYNC.search(line):
                offenders.append(f"{path.relative_to(ROOT)}:{number}")
    assert not offenders, (
        "repository universes are mode-scoped; manual re-synchronisation is a "
        "no-op at best and wrong at worst: " + ", ".join(offenders))


def test_no_module_reaches_around_the_descriptor_via_dunder_dict():
    """A ``__dict__`` read would silently return the wrong universe (or none)."""
    offenders = []
    for path in sorted((ROOT / "feathered_app").rglob("*.py")) + [ROOT / "app.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and isinstance(node.func.value, ast.Attribute)
                    and node.func.value.attr == "__dict__"):
                continue
            if node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in {
                    "repo_rows", "transaction_repo_rows", "mirror_repo_rows"}:
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    assert not offenders, (
        "use self.repository_rows() for a non-raising read: " + ", ".join(offenders))
