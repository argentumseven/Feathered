"""Explicit host dependencies for desktop and headless application mixins.

The GUI and CLI can supply separate instances, so test-time overrides and
application customization no longer mutate module globals in every mixin.
``legacy_facade_ports`` is a narrow compatibility adapter for old callers that
assign the supported ``app.<dependency>`` facade aliases.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable

from core import (evidence_relationship, human_size, mirrors_are_distinct,
                  spot_compare_artifact_urls, spot_compare_peer_artifact_urls)


@dataclass
class ApplicationDependencyPorts:
    human_size: Callable[[int], str] = human_size
    datetime: Any = datetime
    evidence_relationship: Callable[..., str] = evidence_relationship
    mirrors_are_distinct: Callable[..., tuple] = mirrors_are_distinct
    spot_compare_artifact_urls: Callable[..., tuple] = spot_compare_artifact_urls
    spot_compare_peer_artifact_urls: Callable[..., tuple] = spot_compare_peer_artifact_urls


# Standalone historical mixin hosts use this fallback when not composed by App.
# Unlike the previous facade, changing one port does not modify any module's
# globals, nor can it overwrite an independently configured application's ports.
legacy_facade_ports = ApplicationDependencyPorts()


def ports_for(host: object) -> ApplicationDependencyPorts:
    """Resolve injected ports without triggering uninitialized Tk.__getattr__."""
    state = getattr(host, "__dict__", None)
    if state is not None:
        injected = state.get("_app_dependencies")
        if injected is not None:
            return injected
    return legacy_facade_ports
