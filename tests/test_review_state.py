"""Regression contracts for GUI-independent review state and legacy adapters."""
from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest

from feathered_app.review_state import ReviewState, ReviewStateMixin


def result(*names: str, unresolved=()):
    return SimpleNamespace(
        selected=[SimpleNamespace(nevra=name, size=10) for name in names],
        unresolved=[SimpleNamespace(name=name) for name in unresolved],
        ignored_unresolved=[], conflicts=[], total_size=10 * len(names),
        unresolved_notes={}, reasons={}, roots=[], mirror_repository_summaries=[],
    )


def test_review_state_imports_no_tk_widgets_or_application_root():
    source = (Path(__file__).resolve().parents[1] / "feathered_app/review_state.py").read_text()
    imports = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.append(node.module or "")
    assert not any(name.startswith(("tkinter", "app", "feathered_app.ui",
                                    "feathered_app.application")) for name in imports)


def test_separate_review_sessions_do_not_share_mutable_collections():
    first, second = ReviewState(), ReviewState()
    first.result_rows["pkg"] = "row"
    first.item_states["pkg"] = {"status": "done"}
    first.picked.add("pkg")
    first.ignored_unresolved.add("missing")
    first.last_warnings.append("trust issue")
    first.unresolved_rows["row"] = "missing"
    assert second.result_rows == {}
    assert second.item_states == {}
    assert second.picked == set()
    assert second.ignored_unresolved == set()
    assert second.last_warnings == []
    assert second.unresolved_rows == {}


def test_analysis_keeps_explicit_empty_pick_on_identical_closure():
    state = ReviewState()
    initial = result("a", "b")
    assert not state.accept_result(initial, signature=(1,), pick_mode=True, unresolved_keys=set())
    assert state.picked == {"a", "b"}
    state.picked.clear()
    state.result_page = 2
    state.item_states["a"] = {"status": "downloaded"}
    # A build resolves a distinct result object with the same closure.
    again = result("a", "b")
    assert not state.accept_result(again, signature=(1,), pick_mode=True, unresolved_keys=set())
    assert state.picked == set(), "empty selection must never silently become an all-download"
    assert state.result_page == 0
    assert state.item_states == {}
    state.result_page = 1
    assert state.accept_result(again, signature=(1,), pick_mode=True, unresolved_keys=set())
    assert state.result_page == 1


def test_new_package_closure_reinitializes_selection():
    state = ReviewState()
    state.accept_result(result("a", "b"), signature=1, pick_mode=True, unresolved_keys=set())
    state.picked = {"a"}
    state.accept_result(result("a", "b", "c"), signature=2,
                        pick_mode=True, unresolved_keys=set())
    assert state.picked == {"a", "b", "c"}
    assert state.picked_closure == {"a", "b", "c"}


def test_no_picking_mode_does_not_retain_old_choice():
    state = ReviewState()
    state.accept_result(result("a"), signature=1, pick_mode=True, unresolved_keys=set())
    state.accept_result(result("a"), signature=1, pick_mode=False, unresolved_keys=set())
    assert state.picked == set()
    assert state.picked_closure is None


def test_waivers_are_intersected_with_current_unresolved_requirements():
    state = ReviewState(ignored_unresolved={"old", "still"})
    current = result("pkg", unresolved=("still", "new"))
    state.accept_result(current, signature=1, pick_mode=False,
                        unresolved_keys={"still", "new"})
    assert state.ignored_unresolved == {"still"}
    assert current.ignored_unresolved == ["still"]
    assert [r.name for r in state.blocking(current, requirement_key=lambda r: r.name)] == ["new"]


def test_waive_only_rows_on_active_review_page_and_restore():
    state = ReviewState(unresolved_rows={"issue-1": "missing-b", "issue-2": "missing-a"})
    current = result(unresolved=("missing-a", "missing-b"))
    state.last_result = current
    assert not state.waive_rows(["package-row", "unknown"])
    assert current.ignored_unresolved == []
    assert state.waive_rows(["issue-1", "issue-2", "issue-1"])
    assert state.ignored_unresolved == {"missing-a", "missing-b"}
    assert current.ignored_unresolved == ["missing-a", "missing-b"]
    state.restore_waivers()
    assert state.ignored_unresolved == set()
    assert current.ignored_unresolved == []


@pytest.mark.parametrize("action, initial, expected", [
    ("all", {"a"}, {"a", "b", "c"}),
    ("none", {"a"}, set()),
    ("invert", {"a"}, {"b", "c"}),
    ("roots", {"a", "c"}, {"b"}),
    ("highlighted", {"a"}, {"c"}),
])
def test_bulk_selection_operates_on_full_closure(action, initial, expected):
    state = ReviewState(picked=set(initial))
    assert state.bulk_pick(action, available={"a", "b", "c"},
                           roots={"b"}, highlighted={"c"})
    assert state.picked == expected
    assert state.picked_closure == {"a", "b", "c"}


def test_empty_highlight_does_not_erase_package_selection():
    state = ReviewState(picked={"a"})
    assert not state.bulk_pick("highlighted", available={"a", "b"}, highlighted=set())
    assert state.picked == {"a"}


def test_toggle_returns_checked_state():
    state = ReviewState(picked={"a"})
    assert not state.toggle("a")
    assert state.picked == set()
    assert state.toggle("b")
    assert state.picked == {"b"}


def test_stale_analysis_discards_result_and_page_but_not_future_waiver_candidates():
    state = ReviewState(ignored_unresolved={"req"}, picked={"pkg"}, result_page=4)
    state.last_result = result("pkg", unresolved=("req",))
    state.analysis_signature = (1,)
    state.result_rows = {"pkg": "row"}
    state.item_states = {"pkg": {"status": "done"}}
    state.last_warnings = ["issue"]
    state.discard_stale_result()
    assert state.last_result is None
    assert state.analysis_signature is None
    assert state.result_rows == {}
    assert state.item_states == {}
    assert state.result_page == 0
    assert state.last_warnings == []
    assert state.ignored_unresolved == {"req"}
    next_result = result("different", unresolved=("different-req",))
    state.accept_result(next_result, signature=(2,), pick_mode=False,
                        unresolved_keys={"different-req"})
    assert next_result.ignored_unresolved == []


def test_real_app_exposes_legacy_review_fields_only_through_owned_state():
    import app

    shell = object.__new__(app.App)
    assert shell.__dict__ == {}
    with pytest.raises(AttributeError, match="last_result"):
        _ = object.__getattribute__(shell, "last_result")
    assert shell.__dict__ == {}
    shell.last_result = result("a")
    shell.picked = {"a"}
    shell.ignored_unresolved = {"unresolved"}
    shell._result_item_states = {"a": {"status": "done"}}
    state = shell.review_state
    assert state.last_result is shell.last_result
    assert state.picked is shell.picked
    assert state.ignored_unresolved is shell.ignored_unresolved
    assert state.item_states is shell._result_item_states
    assert "last_result" not in shell.__dict__
    shell.app_state.analysis.picked = set()
    assert state.picked == set()


def test_direct_legacy_dict_injection_migrates_once_and_delete_resets():
    class Shell(ReviewStateMixin):
        pass

    host = Shell()
    host.__dict__["picked"] = {"legacy"}
    host.__dict__["result_page"] = 3
    assert host.picked == {"legacy"}
    assert host.review_state.result_page == 3
    assert "picked" not in host.__dict__
    host.__dict__["picked"] = {"overridden"}
    assert host.picked == {"overridden"}
    del host.picked
    assert host.picked == set()
    assert host.review_state.result_page == 3
    del host.result_page
    assert host.result_page == 0


def test_review_methods_can_be_used_without_full_tk_app():
    from feathered_app.application.selection import SelectionMixin

    class Host(ReviewStateMixin, SelectionMixin):
        def _format_requirement_backend(self, item):
            return item.name

    host = Host()
    host.ignored_unresolved = {"missing"}
    current = result(unresolved=("missing", "other"))
    host.last_result = current
    assert [r.name for r in host._blocking_unresolved()] == ["other"]


def test_actual_desktop_review_adopts_result_without_storing_fields_on_app(tmp_path, monkeypatch):
    """Exercise the real Tk composition, not only the pure state helper."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    import app

    window = app.App()
    try:
        current = result()
        # Isolate UI composition from repository scan/parameter derivation;
        # the analysis result still travels through the real _show_result.
        window._parameter_signature = lambda: ("frozen",)
        window._render_result_page = lambda _result: None
        window._refresh_download_size_preview = lambda _result: None
        window._pick_mode = lambda: True
        window._show_result(current)
        assert window.last_result is current is window.review_state.last_result
        assert window.picked == set()
        assert window.picked_closure == set()
        assert window.review_state.analysis_signature == ("frozen",)
        assert "last_result" not in window.__dict__
        assert "picked" not in window.__dict__
    finally:
        window.destroy()
