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


def _ui(window=None, tree=None, single_mode=False):
    ui = feather_app.App.__new__(feather_app.App)
    ui.single_browser_window = window
    ui.__dict__["single_browser_tree"] = tree
    ui._single_mode = lambda: single_mode
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


# The chooser has two forms and the tests above only described one of them.
# "Choose exact packages" renders the tree inline on the Repositories pane and
# never creates a Toplevel, so gating the Add action on a popup window stopped
# packages being added at all in the mode operators actually use. These pin the
# inline form down.


class _Pkg:
    def __init__(self, nevra):
        self.nevra = nevra
        self.name = nevra.split("-")[0]
        self.repo = type("R", (), {"source_identity": "src", "name": "base"})()


class _Var:
    def __init__(self): self.value = ""
    def set(self, value): self.value = value
    def get(self): return self.value


def _inline_ui(rows=("r0",), pkg=None, already=()):
    ui = _ui(window=None, tree=_Tree(rows), single_mode=True)
    ui.single_browser_rows = {"r0": pkg or _Pkg("nginx-1.24-1.x86_64")}
    ui.selected_packages = list(already)
    ui.browser_mode = "exact"
    for name in ("_refresh_selected_packages", "_sync_workload_repo_state",
                 "_update_source_status", "_refresh_repo_tree_if_open"):
        setattr(ui, name, lambda *a, **k: None)
    ui._log = lambda _m: None
    ui.summary_var = _Var()
    ui.single_browser_status_var = _Var()
    ui.loaded_signature = None
    ui.loaded_packages = []
    ui.last_result = None
    return ui


def test_inline_chooser_without_a_popup_still_adds(monkeypatch):
    """The regression: no Toplevel exists in exact-packages mode."""
    _capture(monkeypatch)
    ui = _inline_ui()

    feather_app.App.use_selected_single_package(ui)

    assert [p.nevra for p in ui.selected_packages] == ["nginx-1.24-1.x86_64"]


def test_inline_chooser_accumulates_several_packages(monkeypatch):
    _capture(monkeypatch)
    ui = _inline_ui(already=[_Pkg("curl-8.5-1.x86_64")])

    feather_app.App.use_selected_single_package(ui)

    assert len(ui.selected_packages) == 2


def test_inline_add_keeps_its_tree_reference(monkeypatch):
    """A successful add must not clear the inline tree: it is still on screen,
    and discarding the reference is what sent the next Add into recovery."""
    _capture(monkeypatch)
    ui = _inline_ui()

    feather_app.App.use_selected_single_package(ui)

    assert ui.__dict__.get("single_browser_tree") is not None


def test_re_adding_the_same_package_inline_reports_instead_of_re_rendering(monkeypatch):
    """The originally reported behaviour, at its root cause."""
    events = _capture(monkeypatch)
    ui = _inline_ui()
    ui._render_repository_workflow = lambda force=False: events.append(("rerender", force))

    feather_app.App.use_selected_single_package(ui)
    feather_app.App.use_selected_single_package(ui)

    assert len(ui.selected_packages) == 1
    assert events == []
    assert "already selected" in ui.single_browser_status_var.get()
