"""Uncached byte streaming shared by legacy core digest entry points.

Algorithm selection and trust policy belong to callers. In particular, this
module neither consults the payload digest ledger nor marks anything verified.
"""
from __future__ import annotations

from pathlib import Path
from typing import Protocol


class Digest(Protocol):
    def update(self, data: bytes, /) -> None: ...
    def hexdigest(self) -> str: ...


def stream_digest(path: Path, digest: Digest) -> str:
    """Read the complete file using the caller's already-created digest object."""
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()
