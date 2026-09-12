"""The footer is a status line and must stay one.

The footer packs against the bottom of the window and its label wraps to the
available width. A multi-line failure -- a unified-mirror conflict report is
twenty-plus lines -- therefore wraps to forty-odd rendered rows, grows the
label, grows the footer, and squeezes the wizard pane upward until it is
unusable. The failure that most needs the operator to read the screen was the
one that destroyed it.

Two independent guards, and both are tested here because either alone is
insufficient: the text is condensed at every write site, and the label carries a
pinned height so a future caller that bypasses the condenser cannot bring the
growth back.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import core
from feathered_app.status_text import (
    FOOTER_STATUS_LINES,
    MAX_STATUS_CHARS,
    condense_status_text,
    first_line,
)
from mirror_unification import conflict_report, unify_mirror_packages


def _big_conflict_report() -> str:
    """The real thing, not a synthetic blob: this is what the operator hits."""
    base = core.RepoSpec("BaseOS", "https://a.invalid/", "dependency")
    vendor = core.RepoSpec("Vendor", "https://b.invalid/", "dependency")

    def pkg(name, source, digest):
        return core.Package(name, "x86_64", "0", "1", "1", f"{name}.rpm", "sha256",
                            digest, source, digests={"sha256": digest}, size=100)

    packages = []
    for index in range(30):
        packages.append(pkg(f"pkg{index}", base, "a" * 64))
        packages.append(pkg(f"pkg{index}", vendor, "b" * 64))
    return conflict_report(unify_mirror_packages(packages, [base, vendor]))


def test_a_real_conflict_report_is_reduced_to_one_line():
    report = _big_conflict_report()
    assert report.count("\n") > 20, "fixture should be a genuinely long message"

    shown = condense_status_text(report)

    assert "\n" not in shown
    assert len(shown) <= MAX_STATUS_CHARS


def test_condensed_text_still_says_what_went_wrong():
    """Truncation must not cost the operator the headline."""
    shown = condense_status_text(_big_conflict_report())
    assert "could not be proven identical" in shown


def test_truncation_points_at_the_log_rather_than_just_stopping():
    shown = condense_status_text("word " * 200)
    assert shown.endswith("see Log for the full message")
    assert "\u2026" in shown


def test_short_messages_pass_through_untouched():
    for message in ("Ready", "Downloading 41 of 300", "Analysis complete"):
        assert condense_status_text(message) == message


def test_embedded_newlines_are_collapsed_even_when_short():
    """The label wraps on width, so a newline costs a rendered row regardless."""
    shown = condense_status_text("Failed\n  because of\n\n  three things")
    assert shown == "Failed because of three things"


def test_deliberate_space_runs_survive():
    """The footer's state separator is formatting, not stray whitespace."""
    assert condense_status_text("Review required  |  paused") == "Review required  |  paused"


def test_truncation_prefers_a_word_boundary_but_survives_one_long_token():
    assert not condense_status_text("word " * 100).split("\u2026")[0].endswith("wo")
    monster = "x" * 500
    shown = condense_status_text(monster)
    assert len(shown) <= MAX_STATUS_CHARS




@pytest.mark.parametrize("value", [None, "", "   "])
def test_blank_input_produces_blank_output(value):
    assert condense_status_text(value) == ""
    assert first_line(value) == ""


def test_first_line_skips_leading_blank_lines():
    assert first_line("\n\n  Unified mirror refused\nmore detail") == "Unified mirror refused"


def test_every_status_write_goes_through_the_condenser():
    """A write that bypasses it is how this bug comes back."""
    import ast

    source = (ROOT / "feathered_app" / "application" / "operations.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    offenders = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "set"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "status_var"):
            continue
        # One documented fallback for hosts without the mixin; it condenses
        # inline, so check that rather than exempting the line blindly.
        if (node.args and isinstance(node.args[0], ast.Call)
                and getattr(node.args[0].func, "id", "") == "condense_status_text"):
            continue
        offenders.append(node.lineno)
    assert not offenders, (
        "call _set_footer_status instead of setting status_var directly: "
        + ", ".join(map(str, offenders)))


def test_set_footer_status_condenses_and_returns_what_is_shown():
    from feathered_app.application.operations import OperationsMixin

    class Var:
        def __init__(self):
            self.value = None

        def set(self, value):
            self.value = value

    shell = SimpleNamespace()
    var = Var()
    shell.__dict__["status_var"] = var
    report = _big_conflict_report()

    shown = OperationsMixin._set_footer_status(shell, report)

    assert shown == var.value
    assert len(shown) <= MAX_STATUS_CHARS
    assert "\n" not in shown


def test_set_footer_status_is_safe_with_no_widget():
    from feathered_app.application.operations import OperationsMixin

    assert OperationsMixin._set_footer_status(SimpleNamespace(), "anything") != ""


def test_status_label_height_is_pinned_in_the_layout():
    """The structural guard: geometry is bounded even if the condenser is not used."""
    source = (ROOT / "feathered_app" / "ui" / "layout.py").read_text(encoding="utf-8")
    assert "height=FOOTER_STATUS_LINES" in source
    assert source.count("height=FOOTER_STATUS_LINES") >= 2, (
        "pin the height at construction and on every reconfigure")
    assert FOOTER_STATUS_LINES <= 2
