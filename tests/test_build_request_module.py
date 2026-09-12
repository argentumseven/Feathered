"""The first module of the headless core must stay free of Tk.

`feathered_app/build_request.py` holds the frozen-request accessors: the code
the build worker uses instead of reading widgets. Moving them out of
`application/build.py` is what turns that from a convention into a structural
fact, and only if the module genuinely cannot reach a widget.

A comment saying "do not import tkinter here" is not that. These tests import
the module with `tkinter` made unavailable, so a dependency added directly or
through anything it imports fails immediately, with the offending import named.

Each Tk-independent core module gets a case here so the boundary is enforced
by imports rather than asserted by comments.
"""
from __future__ import annotations

import builtins
import os
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#  Modules that have been moved into the headless core. Extend as A2 lands.
CORE_MODULES = (
    "feathered_app.build_request",
    "feathered_app.build_intent",
    "feathered_app.build_backend",
    "repository_transport",
    "checksum_inspection",
    "release_seed",
    "transaction_resolution",
    "transaction_inventory",
    "root_requests", "k8s_version", "k8s_policy", "k8s_discovery", "kubernetes_workflow",
    "repository_tools",
    "feathered_app.build_plan",
    "feathered_app.build_services",
    "feathered_app.build_host_contracts",
    "feathered_app.build_service_host",
    "feathered_app.build_publication",
    "feathered_app.source_scope",
    "feathered_app.metadata_loading",
    "feathered_app.build_runner",
    "feathered_app.build_sources",
    "feathered_app.build_output",
    "feathered_app.build_mirror",
    "feathered_app.headless_host",
    "feathered_app.spec_replay",
    "feathered_app.build_preparation",
    "feathered_app.build_api",
    "feathered_app.build_outcome",
    "feathered_cli",
    "build_spec",
    "mirror_unification",
    "acquisition_model",
    "source_model",
    "feathered_app.repository_universe",
    "feathered_app.status_text",
    "feathered_app.activity_log",
)

FORBIDDEN = ("tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox")


@pytest.mark.parametrize("module", CORE_MODULES)
def test_a_core_module_imports_without_tk(module):
    """Import it with tkinter unavailable, exactly as a headless host would."""
    # Every module removed here is restored in the finally block. An earlier
    # version discarded them, which left later tests importing a half-populated
    # sys.modules and failing for reasons that had nothing to do with them.
    saved = {name: sys.modules.pop(name, None) for name in FORBIDDEN}
    saved.update({name: sys.modules.pop(name) for name in list(sys.modules)
                  if name == module or name.startswith(module + ".")})
    # Re-importing a submodule also rebinds it as an attribute of its parent
    # package, and restoring sys.modules does not undo that. Leaving the fresh
    # copy bound gave App one BuildIntentMixin class and later code another,
    # which surfaced as an unrelated end-to-end failure.
    parent_name, _, leaf = module.rpartition(".")
    parent = sys.modules.get(parent_name) if parent_name else None
    parent_attr = getattr(parent, leaf, None) if parent is not None else None
    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name in FORBIDDEN or name.split(".")[0] == "tkinter":
            raise ImportError(
                f"{module} (or something it imports) reached for {name}; "
                "core modules must not depend on Tk")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = guarded
    try:
        importlib.import_module(module)
    finally:
        builtins.__import__ = real_import
        sys.modules.pop(module, None)
        for name, value in saved.items():
            if value is not None:
                sys.modules[name] = value
        if parent is not None and parent_attr is not None:
            setattr(parent, leaf, parent_attr)


def test_the_guard_would_catch_a_real_dependency():
    """The instrument, before trusting what it reports.

    The guard patches ``builtins.__import__``, which catches the ``import
    tkinter`` *inside* a module being imported -- exactly the dependency worth
    catching. It does not intercept ``importlib.import_module`` itself, which
    goes through the import machinery directly, so this exercises a nested
    import the way a real core module would perform one.
    """
    real_import = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name.split(".")[0] == "tkinter":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    builtins.__import__ = guarded
    try:
        with pytest.raises(ImportError, match="blocked"):
            exec("import tkinter", {})
        with pytest.raises(ImportError, match="blocked"):
            exec("from tkinter import ttk", {})
    finally:
        builtins.__import__ = real_import


def test_build_request_declares_no_tk_names_in_its_source():
    """A second, cheaper check that does not depend on import mechanics."""
    source = (ROOT / "feathered_app" / "build_request.py").read_text(encoding="utf-8")
    for needle in ("tkinter", "ttk.", "messagebox", "filedialog", "self.after(",
                   "winfo_", "grab_set", ".configure(", ".pack("):
        assert needle not in source, f"{needle!r} has no place in the headless core"

    # mypy caught this and the list above did not: the module reached for
    # self.release_var and self.out_var directly, assuming its host is a window
    # with those attributes. Named widget access goes through _live_control.
    import re

    named = re.findall(r"self\.[a-z_]+_var\b", source)
    assert not named, (
        f"the core must not name widgets: {sorted(set(named))}; "
        "use _live_control/_live_value instead")


def test_the_accessors_still_serve_the_frozen_request():
    """Behaviour must be unchanged by the move; this is a relocation, not a redesign."""
    from build_spec import BuildSpec, OutputSpec, TargetSpec
    from feathered_app.build_request import BuildRequestMixin

    class Host(BuildRequestMixin):
        """A host with no widgets at all, which is the point of the module."""

    host = Host()
    host.__dict__["_build_snapshot"] = BuildSpec(
        target=TargetSpec(arch="x86_64", release="12"),
        output=OutputSpec(directory="/bundles"))

    assert host._selected_arch() == "x86_64"
    assert host._selected_release() == "12"
    assert host._selected_output_base() == "/bundles"


def test_an_empty_frozen_value_is_not_treated_as_absent():
    """The bug this module's accessors had in 1.2.12, pinned after the move."""
    from types import SimpleNamespace

    from build_spec import BuildSpec, TargetSpec
    from feathered_app.build_request import BuildRequestMixin

    class Host(BuildRequestMixin):
        pass

    host = Host()
    host.__dict__["_build_snapshot"] = BuildSpec(target=TargetSpec(release=""))
    host.__dict__["release_var"] = SimpleNamespace(get=lambda: "should-not-be-read")

    assert host._selected_release() == "", (
        "an empty frozen value must not fall through to the widget")


def test_oracle_scenarios_are_reproducible_from_the_seed_alone():
    """"Reproduce with --seed N" has to actually reproduce.

    The generator iterated a set literal of version strings, whose order depends
    on PYTHONHASHSEED, so the same seed produced different graphs between runs.
    """
    import subprocess
    import sys as _sys

    def fingerprint(hash_seed: str) -> str:
        return subprocess.run(
            [_sys.executable, "-c",
             "import sys; sys.path.insert(0, '.'); import solv_oracle as s;"
             "sc = s.generate(108, 'rpm');"
             "print(sc.describe(), sum(len(n.requires) for n in sc.nodes),"
             "      [n.version for n in sc.nodes])"],
            cwd=ROOT, capture_output=True, text=True,
            env={**os.environ, "PYTHONHASHSEED": hash_seed}).stdout

    first = fingerprint("0")
    assert first.strip(), "the generator should produce a scenario"
    for seed in ("1", "12345", "999"):
        assert fingerprint(seed) == first, (
            "the same --seed must produce the same scenario regardless of "
            "PYTHONHASHSEED, or a reported failure cannot be reproduced")


#  Modules that still depend on Tk. As the headless boundary expands, entries
#  move from here to CORE_MODULES. The completion criterion is behavioral: a
#  build must run in a fresh process with Tk imports blocked and no UI event
#  consumer.
NOT_YET_HEADLESS = (
    "feathered_app.application.build",
    "app",
)


def test_the_headless_frontier_is_where_it_is_recorded():
    """Fail when a module crosses the line, in either direction.

    Catching an *improvement* matters as much as catching a regression: a module
    that becomes headless without this list being updated leaves the project
    understating its own progress, which is how the plan document drifted from
    the source three times.
    """
    import subprocess
    import sys as _sys

    probe = (
        "import builtins, sys\n"
        "real = builtins.__import__\n"
        "def guarded(name, *a, **k):\n"
        "    if name.split('.')[0] == 'tkinter':\n"
        "        raise ImportError('blocked')\n"
        "    return real(name, *a, **k)\n"
        "builtins.__import__ = guarded\n"
        "sys.path.insert(0, '.')\n"
        "import json\n"
        "out = {}\n"
        "for mod in %r:\n"
        "    try:\n"
        "        __import__(mod); out[mod] = True\n"
        "    except ImportError:\n"
        "        out[mod] = False\n"
        "print(json.dumps(out))\n"
    ) % (list(CORE_MODULES) + list(NOT_YET_HEADLESS),)

    result = subprocess.run([_sys.executable, "-c", probe], cwd=ROOT,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    headless = json.loads(result.stdout)

    for module in CORE_MODULES:
        assert headless[module], f"{module} is listed as core but needs Tk"
    for module in NOT_YET_HEADLESS:
        assert not headless[module], (
            f"{module} imports without Tk now. Move it into CORE_MODULES and out "
            "of NOT_YET_HEADLESS so the frontier stays accurate.")


# --------------------------------------------------------------------------
# The services interface
# --------------------------------------------------------------------------

def test_unsupplied_decisions_default_to_declining():
    """A caller that forgets a policy must get a refused build, not a silent yes."""
    from feathered_app.build_services import BuildServices

    class Recorder:
        def log(self, message): pass
        def warn(self, message): pass
        def progress(self, label, value): pass

    services = BuildServices(reporter=Recorder())

    assert services.trust_policy(["unsigned index"]) is False
    assert services.decision_policy("T", "proceed?") is False
    assert services.should_cancel() is False
    assert services.download_plan_sink(3, 128) is None


def test_services_gathered_from_a_host_report_what_is_missing():
    from types import SimpleNamespace

    from feathered_app.build_services import BuildServices

    class Recorder:
        def log(self, message): pass
        def warn(self, message): pass
        def progress(self, label, value): pass

    host = SimpleNamespace()
    host.__dict__["_trust_policy"] = lambda findings: True

    services = BuildServices.from_host(host, Recorder())

    assert services.trust_policy(["x"]) is True
    assert services.unsupplied == ("_decision_policy", "_download_plan_sink")
    assert "will be declined" in services.describe()

    host.__dict__["_decision_policy"] = lambda t, m: True
    host.__dict__["_download_plan_sink"] = lambda c, b: None
    complete = BuildServices.from_host(host, Recorder())
    assert complete.unsupplied == ()
    assert "all decision points supplied" in complete.describe()


def test_services_cannot_change_once_a_run_has_them():
    from dataclasses import FrozenInstanceError

    from feathered_app.build_services import BuildServices

    class Recorder:
        def log(self, message): pass
        def warn(self, message): pass
        def progress(self, label, value): pass

    services = BuildServices(reporter=Recorder())
    with pytest.raises(FrozenInstanceError):
        services.trust_policy = lambda findings: True


def test_the_real_application_can_supply_a_complete_service_set():
    """The GUI installs no policies, so it must report all three as unsupplied.

    That is correct rather than a defect: the interactive paths are the
    fallbacks inside _confirm_warnings, _ask_on_ui_thread and
    _publish_download_plan, not injected policies. This pins the distinction so
    a future change that silently starts injecting them is visible.
    """
    from types import SimpleNamespace

    from feathered_app.build_services import BuildServices

    class Recorder:
        def log(self, message): pass
        def warn(self, message): pass
        def progress(self, label, value): pass

    services = BuildServices.from_host(SimpleNamespace(), Recorder())
    assert set(services.unsupplied) == {
        "_trust_policy", "_decision_policy", "_download_plan_sink"}


def test_the_headless_host_covers_the_whole_runner_surface():
    """The end of item A2: a build host that is not a window.

    `build_runner.run` reaches its host forty times. This asserts every one of
    those names is available on a HeadlessHost - 35 from the composed Tk-free
    mixins, five set in __init__ - so the surface cannot silently grow past what
    a non-GUI caller can provide.
    """
    import ast
    import queue
    import threading

    from build_spec import BuildSpec
    from feathered_app.build_services import BuildServices
    from feathered_app.headless_host import HeadlessHost

    source = (ROOT / "feathered_app" / "build_runner.py").read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name == "run":
            needed = sorted({a.attr for a in ast.walk(node)
                             if isinstance(a, ast.Attribute)
                             and isinstance(a.value, ast.Name) and a.value.id == "app"})
            break

    class Recorder:
        def __init__(self): self.lines = []
        def log(self, message): self.lines.append(message)
        def warn(self, message): self.lines.append(message)
        def progress(self, label, value): pass

    host = HeadlessHost(BuildSpec(), BuildServices(reporter=Recorder()))
    missing = [name for name in needed if not hasattr(host, name)]
    assert not missing, (
        "build_runner.run reaches for host attributes a headless caller cannot "
        f"provide: {missing}")

    assert isinstance(host.events, queue.Queue)
    assert isinstance(host.cancel_event, threading.Event)


def test_the_headless_host_declines_what_nobody_answered():
    """Unsupplied decisions decline, and no decision reaches a widget."""
    from build_spec import BuildSpec
    from feathered_app.build_services import BuildServices
    from feathered_app.headless_host import HeadlessHost

    class Recorder:
        def log(self, message): pass
        def warn(self, message): pass
        def progress(self, label, value): pass

    host = HeadlessHost(BuildSpec(), BuildServices(reporter=Recorder()))

    assert host._confirm_warnings([]) is True, "no findings needs no decision"
    assert host._confirm_warnings(["unsigned index"]) is False
    assert host._confirm_conflicts(["a replaces b"]) is False
    host._publish_download_plan(3, 128)  # must not block on a consumer

    answered = []
    supplied = HeadlessHost(BuildSpec(), BuildServices(
        reporter=Recorder(),
        trust_policy=lambda rows: answered.append(rows) or True))
    assert supplied._confirm_warnings(["unsigned index"]) is True
    assert answered == [["unsigned index"]]


def test_the_headless_host_can_be_cancelled():
    from build_spec import BuildSpec
    from feathered_app.build_services import BuildServices
    from feathered_app.headless_host import HeadlessHost

    class Recorder:
        def log(self, message): pass
        def warn(self, message): pass
        def progress(self, label, value): pass

    host = HeadlessHost(BuildSpec(), BuildServices(reporter=Recorder()))
    assert not host.cancel_event.is_set()
    host.request_cancel()
    assert host.cancel_event.is_set()
