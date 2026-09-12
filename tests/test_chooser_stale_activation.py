"""Re-activating the exact-package chooser's Add action after it has closed.

Reported behaviour: picking the same package a second time produced "Select a
package/version row first", wiped the search results, and scrolled the page
somewhere unrelated.

Cause: a successful add destroys the chooser window and clears the cached tree.
A second activation -- a double-click on "Use selected package", or Return
arriving after the window went away -- still called _live_single_browser_tree(),
whose stale-reference recovery calls _render_repository_workflow(force=True).
That rebuilt the entire Repositories workflow, which is what discarded the
search results and moved the scroll position, and it then reported a missing
selection for a chooser the operator could no longer see.

Recovery is now scoped to "the chooser is open but its tree reference went
stale", which is the only situation it was written for.
"""
import app as feather_app
import feathered_app.application.sources as sources


class _Window:
    def __init__(self, alive=True): self._alive = alive
    def winfo_exists(self): return self._alive


class _Tree:
    def __init__(self, rows=()): self._rows = tuple(rows)
    def winfo_exists(self): return True
    def selection(self): return self._rows
    def focus(self): return self._rows[0] if self._rows else ""


def _ui(window=None, tree=None):
    ui = feather_app.App.__new__(feather_app.App)
    ui.single_browser_window = window
    ui.__dict__["single_browser_tree"] = tree
    return ui


def _capture(monkeypatch):
    events = []

    class Box:
        @staticmethod
        def showinfo(_title, message): events.append(("modal", message))

    monkeypatch.setattr(sources, "messagebox", Box)
    return events


def test_chooser_add_after_close_is_silent(monkeypatch):
    """No modal and, crucially, no workflow re-render."""
    events = _capture(monkeypatch)
    ui = _ui(window=None, tree=None)
    ui._render_repository_workflow = lambda force=False: events.append(("rerender", force))

    feather_app.App.use_selected_single_package(ui)

    assert events == []


def test_a_destroyed_chooser_window_counts_as_closed(monkeypatch):
    """winfo_exists() is False after destroy() even though the attribute is set."""
    events = _capture(monkeypatch)
    ui = _ui(window=_Window(alive=False), tree=None)
    ui._render_repository_workflow = lambda force=False: events.append(("rerender", force))

    feather_app.App.use_selected_single_package(ui)

    assert events == []


def test_open_chooser_with_no_row_still_prompts(monkeypatch):
    """The genuine operator error keeps its message."""
    events = _capture(monkeypatch)
    ui = _ui(window=_Window(), tree=_Tree())
    ui._render_repository_workflow = lambda force=False: events.append(("rerender", force))

    feather_app.App.use_selected_single_package(ui)

    assert events == [("modal", "Select a package/version row first.")]


def test_open_chooser_recovers_a_stale_tree(monkeypatch):
    """The 1.2.12 behaviour is preserved where it applies."""
    events = _capture(monkeypatch)
    ui = _ui(window=_Window(), tree=None)

    def render(force=False):
        events.append(("rerender", force))
        ui.single_browser_tree = _Tree(("pkg-0",))
    ui._render_repository_workflow = render

    tree = feather_app.App._live_single_browser_tree(ui)

    assert events == [("rerender", True)]
    assert tree is not None and tree.focus() == "pkg-0"


def test_closed_chooser_never_triggers_a_rerender(monkeypatch):
    """Directly: the re-render is what destroyed the operator's search state."""
    events = _capture(monkeypatch)
    ui = _ui(window=None, tree=None)
    ui._render_repository_workflow = lambda force=False: events.append(("rerender", force))

    assert feather_app.App._live_single_browser_tree(ui) is None
    assert events == []
