from __future__ import annotations

from types import SimpleNamespace

import pytest

from acquisition_model import AcquisitionCapability
import receiver_preflight


class _Var:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


@pytest.mark.parametrize(
    ("mode", "recommends"),
    [
        ("Complete bundle (recommended)", False),
        ("Target-aware complete", False),
        ("Complete + weak dependencies", True),
    ],
)
def test_arch_build_options_do_not_require_inventory(mode, recommends):
    from app import App

    ui = App.__new__(App)
    ui.resolution_pass_budget = 8
    ui.mode_var = _Var(mode)
    ui.inventory_var = _Var("")
    ui._build_snapshot = None
    ui._acquisition_state = lambda: SimpleNamespace(
        capability=AcquisitionCapability.FULL_TRANSACTION)
    ui._build_repository_scope = lambda package_only=False: []
    ui._trust_options = lambda *args, **kwargs: {}
    ui._single_mode = lambda: False
    ui._profile = lambda: SimpleNamespace(package_family="arch")

    opts = App._build_options(ui)

    assert opts.include_dependencies
    assert opts.include_recommends is recommends
    assert opts.target_inventory is None


def test_arch_receiver_preflight_accepts_inventory_free_forward_closure():
    contract = {
        "family": "arch",
        "arch_full_upgrade": False,
        "inventory": None,
        "baseline_required": [],
        "target": {"arch": "x86_64"},
    }
    receiver_preflight.validate(contract, {}, machine="x86_64")


def test_arch_receiver_preflight_still_checks_declared_full_upgrade_snapshot():
    contract = {
        "family": "arch",
        "arch_full_upgrade": True,
        "inventory": None,
        "baseline_required": [],
        "target": {"arch": "x86_64"},
    }
    with pytest.raises(RuntimeError, match="does not contain its inventory snapshot"):
        receiver_preflight.validate(contract, {}, machine="x86_64")


def test_vks_inventory_is_not_a_wizard_navigation_prerequisite():
    import inspect
    from app import App

    source = inspect.getsource(App._validate_wizard_transition)
    assert "INVENTORY_MESSAGE" not in source
    assert "not self.inventory_var.get().strip()" not in source


def test_tooltips_are_owned_by_their_source_lifecycle():
    import inspect
    from app import App

    source = inspect.getsource(App._attach_tooltip)
    assert 'widget.bind("<Unmap>", hide' in source
    assert 'widget.bind("<Destroy>", hide' in source
    assert "_tooltip_windows" in source
    assert "self._dismiss_tooltips()" in inspect.getsource(App.show_pane)
