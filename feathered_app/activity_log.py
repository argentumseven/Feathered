"""A durable copy of the Activity log on the build host.

Every diagnostic Feathered writes today lives in one of two places, and neither
survives the case that matters most. Bundle-side evidence -- provenance.json,
trust-warnings.txt, the build report -- is only written when a build reaches the
publication step. The Activity log is a Python list held in memory, capped at
5000 lines and discarded when the window closes.

So a build that crashes, is cancelled, or fails during resolution leaves nothing
behind on the machine that ran it. Every support conversation about a failure
starts with "it failed" and no artifact, and the operator is often on a machine
they cannot copy text off casually.

This module mirrors the in-memory log to a rotating file under the user state
directory. It is deliberately best-effort in one direction only: a logging
failure must never take down a build, but it also must never silently pretend to
have written something. Failures disable the sink and are surfaced once through
the normal log, so the operator learns that the file is not being written.

Credential redaction happens upstream in ``_log`` before anything reaches here.
This module must not be given raw exception text.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

#  Roughly a few thousand lines of build output. Small enough to attach to a
#  ticket, large enough to hold a full failed resolution.
MAX_BYTES = 2 * 1024 * 1024
KEEP_ROTATIONS = 3
LOG_NAME = "feathered-activity.log"


class ActivityLogFile:
    """Append-only mirror of the Activity log, with size-based rotation."""

    def __init__(self, directory: Path, name: str = LOG_NAME,
                 max_bytes: int = MAX_BYTES, keep: int = KEEP_ROTATIONS):
        self.path = Path(directory) / name
        self.max_bytes = int(max_bytes)
        self.keep = int(keep)
        self.disabled_reason: str = ""

    # -- lifecycle ---------------------------------------------------------

    def open_session(self, header: str = "") -> bool:
        """Start a session block. Returns False if the sink could not be used."""
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        banner = f"===== Feathered session {stamp} ====="
        return self.write(banner if not header else f"{banner}\n{header}")

    def write(self, text: str) -> bool:
        """Append ``text`` as one or more lines. Never raises."""
        if self.disabled_reason:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate_if_needed()
            with self.path.open("a", encoding="utf-8", errors="replace") as handle:
                handle.write(str(text).rstrip("\n") + "\n")
            self._restrict()
            return True
        except OSError as exc:
            #  Disable rather than retry per line: a full disk or a read-only
            #  profile directory would otherwise raise on every log call for the
            #  remainder of the session.
            self.disabled_reason = f"{type(exc).__name__}: {exc}"
            return False

    def write_lines(self, lines: List[str]) -> bool:
        return self.write("\n".join(str(line) for line in lines))

    # -- rotation ----------------------------------------------------------

    def _rotate_if_needed(self) -> None:
        try:
            if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
                return
        except OSError:
            return
        #  Oldest first, so no rename overwrites a file still to be moved.
        for index in range(self.keep, 0, -1):
            source = self.path if index == 1 else self.path.with_suffix(f".{index - 1}")
            target = self.path.with_suffix(f".{index}")
            try:
                if source.exists():
                    os.replace(source, target)
            except OSError:
                return

    def _restrict(self) -> None:
        """Match the 0700 posture of the state directory this lives in."""
        try:
            self.path.chmod(0o600)
        except OSError:
            pass  # Windows and some filesystems do not implement POSIX modes.


def open_activity_log(directory: Optional[Path], header: str = "") -> Optional[ActivityLogFile]:
    """Create and open a sink, or return None if the directory is unusable.

    Returning None rather than a disabled sink keeps the caller's check simple:
    a sink that exists is one that wrote its own session banner successfully.
    """
    if directory is None:
        return None
    sink = ActivityLogFile(directory)
    if not sink.open_session(header):
        return None
    return sink
