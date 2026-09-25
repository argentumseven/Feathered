"""Frozen build-request accessors used by GUI and headless execution.

This module intentionally imports no Tk. `tests/test_build_request_module.py`
enforces that boundary for direct and transitive imports.

These methods exist because Tk variables cannot safely be read from the build
worker thread. `_snapshot_build_inputs` freezes the whole request on the main
thread immediately before the worker is created, and everything the worker needs
is served from that snapshot afterwards. Moving them here is the point where
that becomes structural rather than conventional: code in this file has no
widgets to reach for.

They are a mixin rather than a standalone class only because the rest of the
build path still lives on `App`. As more of A2 lands, this is where it lands.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from build_spec import capture


class _SnapshotMode:
    """Adapts the frozen selection label to the ``.get()`` shape callers expect."""

    __slots__ = ("_host",)

    def __init__(self, host):
        self._host = host

    def get(self):
        return self._host._selected_mode_label()


def live_control(host: object, name: str) -> object:
    """The host's control for ``name``, or None if it has no such thing.

    Module-level so mixins that are not ``BuildRequestMixin`` subclasses (the
    hosts compose them side by side) can share the accessor without calling an
    unbound method on a foreign ``self``.
    """
    return host.__dict__.get(name)


def live_value(host: object, name: str, default: str = "") -> str:
    """The live control's value as text, or ``default`` if absent or unreadable."""
    control = live_control(host, name)
    if control is None:
        return default
    try:
        value = control.get()  # type: ignore[attr-defined]
    except Exception:
        return default
    return default if value is None else str(value)


def build_snapshot_value(host: object, section: str, field: str,
                         default: Any = None) -> Any:
    """Read one frozen request value, or None when no build is running.

    Returning None outside a build is deliberate: the interactive wizard
    must keep reflecting the live controls. Only the worker is pinned. The
    result is ``Any`` because frozen fields are heterogeneous (strings, sets of
    source identities, booleans); callers narrow it for the field they read.
    """
    snapshot = host.__dict__.get("_build_snapshot")
    if snapshot is None:
        return None
    value = getattr(getattr(snapshot, section, None), field, None)
    if value is None:
        return default
    # An empty string is a legitimate frozen value -- an unset release, a
    # blank custom label -- and must not fall through to the widget. Only
    # the absence of a snapshot means "read the live control"; conflating
    # the two put a Tk read back on the worker thread for every build whose
    # release happened to be blank.
    return value


def selected_arch(host: object) -> str:
    """The target architecture, readable from a worker thread.

    ``arch_var`` is a Tk variable and Tk is not thread-safe. Reading one off
    the main thread raises "main thread is not in main loop" on an
    unthreaded Tcl and is undefined behaviour on a threaded one -- it
    happens to work until it does not. The build worker reaches this through
    ``_signature`` -> ``_load_enabled_repos``, so the value is snapshotted on
    the main thread when the build starts and read from the snapshot
    afterwards.

    Build inputs are decided once on the main thread and then read from the
    frozen request rather than from live widgets.
    """
    snapshot = host.__dict__.get("_arch_snapshot")
    if snapshot is not None:
        return snapshot
    # Contract tests call this with a stub host that has no mixin methods,
    # so the snapshot is read through the module-level accessor.
    pinned = build_snapshot_value(host, "target", "arch")
    if pinned is not None:
        return str(pinned)
    variable = host.__dict__.get("arch_var")
    if variable is None:
        # Contract tests drive the cache logic with a stub host that has no
        # widgets at all; an absent control is not an architecture.
        return host.__dict__.get("_last_known_arch", "")
    try:
        return variable.get()
    except RuntimeError:
        # Off the main thread with no snapshot taken: return the last known
        # value rather than crashing a build eight steps in.
        return host.__dict__.get("_last_known_arch", "")


def selected_output_option(host: object, field: str, variable: str, *,
                           flag: bool = False) -> Any:
    """One output/provenance option, from the frozen request or the control.

    These are reached while a build is being prepared, so they must not be
    attribute reads. On a partially constructed widget host, attribute
    access enters the toolkit's ``__getattr__`` and recurses until the
    stack is exhausted, so the symptom is a RecursionError rather than a
    legible AttributeError. A ``__dict__`` read cannot do that.
    """
    section = {"signing_key": "sources", "baseline_path": "target"}.get(field, "output")
    pinned = build_snapshot_value(host, section, field)
    if pinned is not None:
        return bool(pinned) if flag else str(pinned)
    control = host.__dict__.get(variable)
    if control is None:
        return False if flag else ""
    try:
        value = control.get()
    except Exception:
        return False if flag else ""
    return bool(value) if flag else str(value)


def selected_content(host: object, field: str, variable: str) -> str:
    """A Content value from the frozen request, or the live control.

    The build worker reaches dependency mode and version pinning through
    request construction and metadata assembly; both are Tk variables.
    """
    pinned = build_snapshot_value(host, "content", field)
    if pinned is not None:
        return str(pinned)
    return live_value(host, variable)


class BuildRequestMixin:
    """Reads of the frozen request. No widget access, by construction.

    Outside a build there is no snapshot and the live control is the right
    answer, so the accessors fall back to one. That fallback goes through
    ``_live_control``, which asks the host for a value by name, rather than
    reading control attributes off ``self`` as though the core were guaranteed
    to be a window. mypy caught the original form doing exactly that, and the
    source scan in the tests now catches it too.
    """

    def _live_control(self, name: str):
        """The host's control for ``name``, or None if it has no such thing."""
        return live_control(self, name)

    def _live_value(self, name: str, default: str = "") -> str:
        return live_value(self, name, default)

    def _selected_arch(self) -> str:
        """The target architecture, readable from a worker thread."""
        return selected_arch(self)

    def _snapshot_build_inputs(self):
        """Freeze the Tk-owned request before the worker thread exists.

        Called on the main thread immediately before the worker is created.
        Everything the worker needs from a widget is read exactly once, here;
        after this returns, a widget read from the worker is a defect rather
        than merely a risk, and test_build_worker_isolation.py enforces that.
        """
        arch = self._live_value("arch_var")
        self.__dict__["_arch_snapshot"] = arch
        self.__dict__["_last_known_arch"] = arch
        self.__dict__["_build_snapshot"] = capture(self)
        # Folder naming reads the clock, so the request has to freeze the moment
        # as well as the settings. Without this, a build confirmed at 23:59:59
        # and written at 00:00:01 produces two different folder names from the
        # same request, which is what locked_output_folder_name exists to catch.
        self.__dict__.setdefault("_build_naming_time", datetime.now())
        return arch

    def _release_build_inputs(self):
        self.__dict__.pop("_arch_snapshot", None)
        self.__dict__.pop("_build_snapshot", None)
        self.__dict__.pop("_build_naming_time", None)

    def _selected_release(self) -> str:
        """The target release, readable from the worker thread."""
        pinned = self._build_snapshot_value("target", "release")
        if pinned is not None:
            return str(pinned).strip()
        return self._live_value("release_var").strip()

    def _selected_inventory(self) -> str:
        """The target inventory path, readable from a worker or a headless host."""
        pinned = BuildRequestMixin._build_snapshot_value(self, "target", "inventory_path")
        if pinned is not None:
            return str(pinned).strip()
        return self._live_value("inventory_var").strip()

    def _selected_output_option(self, field: str, variable: str, *, flag: bool = False):
        """One output/provenance option, from the frozen request or the control."""
        return selected_output_option(self, field, variable, flag=flag)

    def _selected_output_base(self) -> str:
        """The output directory, readable from the worker thread."""
        pinned = self._build_snapshot_value("output", "directory")
        if pinned is not None:
            return str(pinned).strip()
        return self._live_value("out_var").strip()

    def _selected_mode_label(self) -> str:
        """The Content selection label, readable from the worker thread."""
        pinned = self._build_snapshot_value("content", "selection_mode")
        if pinned is not None:
            return str(pinned)
        return self._live_value("selection_mode_var")

    def _selected_workload_context(self):
        from kubernetes_workflow import WorkloadContext
        import k8s_knowledge
        def read(section, name, variable, default=''):
            value = BuildRequestMixin._build_snapshot_value(self, section, name)
            if value is not None:
                return value
            control = self.__dict__.get(variable)
            return control.get() if control is not None else default
        return WorkloadContext(workload=self._workload().key,
            minor=read('content', 'k8s_minor', 'k8s_minor_var'),
            oldest=read('content', 'apiserver_oldest_minor', 'apiserver_oldest_minor_var'),
            newest=read('content', 'apiserver_newest_minor', 'apiserver_newest_minor_var'),
            pin_baseline=read('content', 'pin_to_inventory_baseline', 'pin_to_inventory_baseline_var', False),
            acknowledged=read('content', 'advisories_acknowledged', 'advisories_acknowledged_var', False),
            image_name=read('content', 'image_baker_name', 'image_baker_name_var', 'feathered-node-additions'),
            platform_note=read('target', 'platform_note', 'platform_note_var'),
            distribution=read('target', 'distribution', 'distro_var'),
            release=read('target', 'release', 'release_var'),
            knowledge=self.__dict__.get('_k8s_knowledge') or k8s_knowledge.bundled())

    def _selected_content(self, field: str, variable: str) -> str:
        """A Content value from the frozen request, or the live control."""
        return selected_content(self, field, variable)

    def _build_snapshot_value(self, section: str, field: str, default=None):
        """Read one frozen request value, or None when no build is running."""
        return build_snapshot_value(self, section, field, default)
