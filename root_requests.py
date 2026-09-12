"""Typed package-root normalization with validation of legacy input records.

Legacy requests are three through seven positional fields. They are not strings
or mappings. Normalization preserves order, duplicates, pins and source identity.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, TypeAlias, overload

OptionalText: TypeAlias = str | None
RootTuple: TypeAlias = tuple[str, OptionalText, OptionalText, OptionalText,
                            OptionalText, OptionalText, OptionalText]
LegacyRoot: TypeAlias = (
    tuple[str, OptionalText, OptionalText]
    | tuple[str, OptionalText, OptionalText, OptionalText]
    | tuple[str, OptionalText, OptionalText, OptionalText, OptionalText]
    | tuple[str, OptionalText, OptionalText, OptionalText, OptionalText, OptionalText]
    | RootTuple
    | list[OptionalText]
)


def _root_name(value: object) -> str:
    if (not isinstance(value, str) or not value or value.startswith("-")
            or any(c in value for c in "\r\n\0")):
        raise RuntimeError(f"Invalid package root name: {value!r}")
    return value


def _optional_text(value: object, field: str) -> OptionalText:
    if value is not None and not isinstance(value, str):
        raise RuntimeError(f"Invalid package request {field}: expected text or None, got {value!r}")
    return value


@dataclass(frozen=True)
class RootRequest:
    name: str
    version: OptionalText = None
    role: OptionalText = None
    repository: OptionalText = None
    architecture: OptionalText = None
    scope: OptionalText = None
    source_identity: OptionalText = None

    def __post_init__(self) -> None:
        _root_name(self.name)
        for field, value in zip(_OPTIONAL_FIELDS, self.as_tuple()[1:]):
            _optional_text(value, field)

    @classmethod
    def from_value(cls, value: object) -> RootRequest:
        """Validate an untrusted record before it reaches backend selection."""
        if isinstance(value, cls):
            # Also validate existing instances, including records restored by a
            # serializer that does not run the dataclass constructor.
            value.__post_init__()
            return value
        if not isinstance(value, (tuple, list)) or not 3 <= len(value) <= 7:
            raise RuntimeError(f"Invalid package request: {value!r}")
        fields = tuple(value) + (None,) * (7 - len(value))
        return cls(_root_name(fields[0]),
                   _optional_text(fields[1], "version"),
                   _optional_text(fields[2], "role"),
                   _optional_text(fields[3], "repository"),
                   _optional_text(fields[4], "architecture"),
                   _optional_text(fields[5], "scope"),
                   _optional_text(fields[6], "source_identity"))

    def as_tuple(self) -> RootTuple:
        return (self.name, self.version, self.role, self.repository,
                self.architecture, self.scope, self.source_identity)

    def __len__(self) -> int:
        return 7

    @overload
    def __getitem__(self, index: int) -> OptionalText: ...
    @overload
    def __getitem__(self, index: slice) -> tuple[OptionalText, ...]: ...
    def __getitem__(self, index: int | slice) -> OptionalText | tuple[OptionalText, ...]:
        return self.as_tuple()[index]

    def __iter__(self) -> Iterator[OptionalText]:
        return iter(self.as_tuple())


_OPTIONAL_FIELDS = ("version", "role", "repository", "architecture", "scope", "source_identity")
RootInput: TypeAlias = RootRequest | LegacyRoot


def normalize_requests(requests: Iterable[RootInput]) -> list[RootRequest]:
    roots = [RootRequest.from_value(request) for request in requests]
    by_name: dict[str, list[RootRequest]] = {}
    for root in roots:
        for prior in by_name.get(root.name, []):
            for field, left, right in (
                    ("version", prior.version, root.version),
                    ("architecture", prior.architecture, root.architecture),
                    ("source_identity", prior.source_identity, root.source_identity)):
                if left and right and left != right:
                    raise RuntimeError(f"Contradictory {field} requests for {root.name}: {left!r} and {right!r}")
        by_name.setdefault(root.name, []).append(root)
    return roots
