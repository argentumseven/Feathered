"""Package-family-neutral artifact contracts.

RPM, DEB, and ALPM package models are intentionally different domain types,
but payload acquisition and verification operate on the same small structural
surface.  Keeping that surface in one protocol prevents shared helpers from
quietly becoming RPM-specific during refactors.
"""
from __future__ import annotations

from typing import Dict, Optional, Protocol

from core_models import ArtifactVerification
from repository_config import RepoSpec


class PackageArtifact(Protocol):
    """Structural contract required by shared payload/verification helpers."""

    @property
    def name(self) -> str: ...

    @property
    def size(self) -> int: ...

    @property
    def checksum_type(self) -> str: ...

    @property
    def checksum(self) -> str: ...

    @property
    def digests(self) -> Dict[str, str]: ...

    @property
    def repo(self) -> RepoSpec: ...

    @property
    def location(self) -> str: ...

    @property
    def verification(self) -> Optional[ArtifactVerification]: ...

    @property
    def nevra(self) -> str: ...


__all__ = ["PackageArtifact"]
