"""Terminal outcomes shared by preparation, execution and command-line callers."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class BuildStatus(str, Enum):
    SUCCESS = 'success'
    INVALID = 'invalid-request'
    DECLINED = 'declined'
    CANCELLED = 'cancelled'
    FAILED = 'failed'
    TIMED_OUT = 'timed-out'


@dataclass(frozen=True)
class BuildOutcome:
    status: BuildStatus
    message: str
    output_path: str | None = None

    @property
    def exit_code(self) -> int:
        return {BuildStatus.SUCCESS: 0, BuildStatus.FAILED: 1,
                BuildStatus.DECLINED: 2, BuildStatus.TIMED_OUT: 4,
                BuildStatus.INVALID: 5, BuildStatus.CANCELLED: 5}[self.status]
