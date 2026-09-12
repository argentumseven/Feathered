"""Parse upstream Kubernetes versions without discarding a vendor build suffix."""
from __future__ import annotations
import re
from dataclasses import dataclass

VKR_HINT = 'A VKr identifier is not a Kubernetes version. Read the Kubernetes version from the VKr details; never derive one from the other.'
_PATTERN = re.compile(r'(?:\d+:)?[vV]?(1)\.(\d+)(?:\.(\d+))?((?:[-+~_][A-Za-z0-9.+_~-]+)?)')

@dataclass(frozen=True)
class Version:
    minor: int
    patch: int | None
    qualifier: str = ''
    prerelease: bool = False

    @property
    def line(self) -> str:
        return f'1.{self.minor}'


def parse(value: str, *, require_patch: bool = False, allow_prerelease: bool = False) -> Version:
    match = _PATTERN.fullmatch(value.strip())
    if not match:
        raise ValueError(f'Invalid Kubernetes version {value!r}. Enter 1.minor or 1.minor.patch, optionally with a vendor suffix. {VKR_HINT}')
    patch = int(match[3]) if match[3] else None
    qualifier = match[4]
    prerelease = bool(re.match(r'^[-+~_]+(?:alpha|beta|rc)(?:[.\d_-]|$)', qualifier, re.I))
    if require_patch and patch is None:
        raise ValueError('A complete package version needs a patch component.')
    if prerelease and not allow_prerelease:
        raise ValueError(f'{value!r} is a pre-release; choose a stable minor for repository selection.')
    return Version(int(match[2]), patch, qualifier, prerelease)


def api_minor(value: str) -> int | None:
    if not value.strip():
        return None
    # Syntax here; upstream knowledge supplies non-blocking lifecycle notices.
    if re.fullmatch(r'[0-9]+', value.strip()):
        return int(value.strip())
    return parse(value).minor
