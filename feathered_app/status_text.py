"""Condense operation status text so the footer cannot grow without bound.

The footer packs against the bottom of the window and its status label wraps to
the available width. That combination is fine for "Downloading 41 of 300" and
actively harmful for a multi-line failure: a twenty-five line conflict report
wraps to forty-odd lines, the label grows vertically, the footer grows with it,
and the wizard content is squeezed upward until the pane is unusable. The
failure that most needs the operator to read the screen is the one that destroys
it.

The footer is a status line, not a report. Anything that does not fit belongs in
the Log, which already receives the complete text. This module reduces arbitrary
text to a single line and says where the rest went.

Kept free of Tk so it can be tested directly rather than through a widget.
"""
from __future__ import annotations

import re

#  Roughly two footer lines at the default width. Deliberately a character
#  budget rather than a line count: the label wraps on width, so counting
#  newlines in the source text would not bound the rendered height.
MAX_STATUS_CHARS = 160

#  Rendered height of the footer status label, in text lines. Pinned on the
#  widget so geometry is bounded structurally and not only by the condenser.
FOOTER_STATUS_LINES = 2

SEE_LOG = "  |  see Log for the full message"

#  Only line breaks and tabs are collapsed. Runs of plain spaces are left alone
#  because the footer's "  |  " state separator is deliberate formatting and
#  does not affect rendered height; height is driven by wrapping and newlines.
_LINE_BREAKS = re.compile(r"[ \t]*[\r\n\v\f]+[ \t]*")
_TABS = re.compile(r"\t+")


def condense_status_text(text: object, limit: int = MAX_STATUS_CHARS,
                         suffix: str = SEE_LOG) -> str:
    """Reduce ``text`` to a single line that fits the footer.

    Multi-line input is collapsed to one line, because the label wraps on width
    and embedded newlines would each force another rendered row regardless of
    how short the text is. Runs of plain spaces are preserved: they cost no
    height, and the footer's state separator relies on them.

    Truncation prefers a word boundary, and only falls back to a hard cut when
    the first word is itself longer than the budget. The suffix names the Log so
    a truncated message reads as deliberate rather than as a rendering bug.
    """
    collapsed = _TABS.sub(" ", _LINE_BREAKS.sub(" ", str(text or ""))).strip()
    if len(collapsed) <= limit:
        return collapsed

    #  -1 for the ellipsis itself, or the result overruns the limit by one.
    budget = max(1, limit - len(suffix) - 1)
    head = collapsed[:budget]
    cut = head.rfind(" ")
    if cut >= budget // 2:
        head = head[:cut]
    return head.rstrip(" \t,;:.\u2013-") + "\u2026" + suffix


def first_line(text: object) -> str:
    """The leading line of a message, for callers wanting a headline only."""
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""
