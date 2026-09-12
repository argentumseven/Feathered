from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

# Source launches must locate their bundled modules even when Python omits
# the script directory from sys.path (for example PYTHONSAFEPATH or -I).
# Frozen builds use the packager's importer and do not need a source path.
if not getattr(_sys, "frozen", False):
    _source_root = str(_Path(__file__).resolve().parent)
    if _source_root not in _sys.path:
        _sys.path.insert(0, _source_root)

from feathered_app.context import *  # noqa: F401,F403
from feathered_app.ui.theme import *  # noqa: F401,F403
from feathered_app.ui.theme import _ThemedMessageBox
from feathered_app.ui.layout import LayoutMixin
from feathered_app.ui.panes import PaneMixin
from feathered_app.application.tools import ToolsMixin
from feathered_app.application.selection import SelectionMixin
from feathered_app.persistence.user_state import PersistenceMixin
from feathered_app.application.provenance import ProvenanceMixin
from feathered_app.application.output import OutputMixin
from feathered_app.application.sources import SourcesMixin
from feathered_app.application.media import MediaMixin
from feathered_app.application.build import BuildMixin
from feathered_app.application.discovery import DiscoveryMixin
from feathered_app.application.repositories import RepositoriesMixin
from feathered_app.application.results import ResultsMixin
from feathered_app.application.operations import OperationsMixin
from feathered_app.repository_universe import RepositoryUniverseMixin
from feathered_app.state import _ApplicationStateDescriptor

class App(
    LayoutMixin, PaneMixin, ToolsMixin, SelectionMixin, PersistenceMixin,
    ProvenanceMixin, OutputMixin, SourcesMixin, MediaMixin, BuildMixin,
    DiscoveryMixin, RepositoriesMixin, ResultsMixin, OperationsMixin,
    RepositoryUniverseMixin, tk.Tk,
):
    """Feathered desktop composition root.

    Functional responsibilities live in dedicated modules while this class
    retains the stable public/test surface of earlier releases.
    """

    # Non-data descriptor: existing embedders remain free to shadow this
    # additive state-view API with an instance attribute of the same name.
    app_state = _ApplicationStateDescriptor()

    def __init__(self):
        super().__init__()
        messagebox.bind_root(self)
        self.title(APP_TITLE)
        self.geometry("1120x760")
        self.minsize(900, 620)
        self.events: queue.Queue = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker: threading.Thread | None = None
        # 1.0.43 gives every long-running
        # action one application-wide activity lease.  The lease is separate
        # from ``self.worker`` because checksum inspection also runs in a
        # background thread but historically bypassed the worker guard.
        self.active_operation: str | None = None
        self.active_operation_label = ""
        self._operation_controls: set = set()
        self._operation_saved_states: dict = {}
        self._operation_cancellable = False
        self._activity_job = None
        self._activity_frame = 0
        self._activity_state = "idle"
        self._operation_detail = ""
        # Wheel gestures retain their original scroll owner briefly.  This
        # prevents a fast page scroll from suddenly freezing when the pointer
        # crosses a nested table/combobox, while still letting a deliberate new
        # gesture scroll the nested control.  Wheel events are also coalesced
        # to reduce Tk redraw churn during fast scrolling.
        self._wheel_owner = None
        self._wheel_last_event = 0.0
        self._wheel_pending_target = None
        self._wheel_pending_units = 0
        self._wheel_flush_job = None
        self._wheel_fraction = 0.0
        # validation routing keeps a visible
        # focus ring on the exact card/control that blocked progression.
        self._attention_card = None
        self._attention_widget = None
        self._attention_widget_style = None
        # Review's result surface pulses only during the analysis/preflight
        # portion of a Build operation.  It stops as soon as payload transfer
        # starts so the existing rows never disappear as a progress signal.
        self._review_glow_job = None
        self._review_glow_phase = 0
        # repo_rows/transaction_repo_rows/mirror_repo_rows are mode-scoped views
        # over one RepositoryUniverse. Assigning any of them lands in the right
        # slot on its own; there is nothing left to keep in step by hand.
        self.repo_rows = []
        self.loaded_signature = None
        self.loaded_packages = []
        self.last_result = None
        self.last_warnings: list[str] = []
        self.analysis_signature = None
        self.result_rows: dict = {}
        self.result_page = 0
        self.result_page_size = 1000
        # Package transfer state is retained independently of the currently
        # visible Review page, so navigating during a build does not lose
        # downloaded/failed/verifying status for off-screen rows.
        self._result_item_states: dict[str, dict] = {}
        self.picked: set = set()
        self.picked_closure = None
        # 1.0.39 keeps explicit
        # unresolved waivers separate from the resolver result.  They survive a
        # retry only while the same requirement remains unresolved.
        self.ignored_unresolved: set[str] = set()
        self.unresolved_rows: dict[str, object] = {}
        self.resolution_pass_budget = 0
        # 1.0.40 tracks the exact
        # successfully published bundle directory so Review and build can open
        # the same path the backend actually wrote, rather than reconstructing
        # it from the output base directory later.
        self.last_output_path: Path | None = None
        self.last_wizard_pane = "target"
        # Rail navigation is sequential. Forward rail clicks never bypass the
        # same transition guards used by the Next button.
        # Concrete repository source identities selected for mirror acquisition.
        # Human-readable repository names are labels only and may collide.
        self.mirror_repos: set = set()
        self._mirror_iid_to_source_identity: dict[str, str] = {}
        self._mirror_iid_to_repo_index: dict[str, int] = {}
        # Mirror acquisition owns an isolated repository universe, so changing
        # mirror presets or manual mirror entries cannot rewrite the later
        # workload/package source universe when Content intent changes. The
        # isolation is now structural: see feathered_app/repository_universe.py.
        self.mirror_repo_rows = []
        self.mirror_source_method_var = None
        self._mirror_seen: set = set()
        self._repository_workflow_key = None
        self.transfer_total = 0
        self.transfer_done = 0
        self.transfer_failed = 0
        self.transfer_reused = 0
        self.transfer_bytes = 0
        self.transfer_expected_bytes = 0
        self.transfer_started = 0.0
        self.log_lines: list[str] = []
        self.repo_window = None
        self.repo_tree = None
        self.repo_window_tier = "additional"
        self.base_repo_tree = None
        self.rhsm_last_folder = ""
        self.rhsm_cert = ""
        self.rhsm_key = ""
        self.rhsm_ca = ""
        self.workload_notes: list[str] = []
        self.workloads = load_workloads(self.workload_notes)
        self.selected_packages = []
        self.keystore = self._load_keystore()
        self.vendor_signature_profiles = self._load_vendor_signature_profiles()
        self.entitlement_profiles = {}
        self._load_entitlement_paths()
        self._load_cached_releases()
        self.single_catalog_packages = []
        self.single_catalog_signature = None
        self.single_browser_window = None
        self.single_browser_tree = None
        self.single_browser_rows = {}
        self.single_browser_status_var = None
        self.single_browser_query_var = None
        self._style()
        self._build_ui()
        self._profile_changed()
        self.after(100, self._drain_events)
        self.after(250, self._preflight)


# Keep monkeypatching `app.<dependency>` compatible with the pre-1.2 module.
# Extracted method bodies have module-local references to the same dependencies;
# tests and embedders historically patch the facade module, so propagate such
# assignments to each responsibility module that owns that name.
import sys as _sys
import types as _types

_COMPONENT_MODULES = tuple({
    _sys.modules[base.__module__]
    for base in App.__mro__
    if base is not App and base.__module__.startswith("feathered_app.")
})


class _AppFacadeModule(_types.ModuleType):
    def __setattr__(self, name, value):
        super().__setattr__(name, value)
        for module in _COMPONENT_MODULES:
            if name in module.__dict__:
                module.__dict__[name] = value

_sys.modules[__name__].__class__ = _AppFacadeModule


if __name__ == "__main__":
    App().mainloop()
