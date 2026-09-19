"""Process-level transfer and expansion safety limits."""
from __future__ import annotations

import os


def positive_env_int(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
        return value if value > 0 else default
    except (TypeError, ValueError):
        return default


MAX_METADATA_DOWNLOAD_BYTES = positive_env_int(
    "FEATHERED_MAX_METADATA_DOWNLOAD_BYTES", 256 * 1024 * 1024
)
MAX_METADATA_EXPANDED_BYTES = positive_env_int(
    "FEATHERED_MAX_METADATA_EXPANDED_BYTES", 768 * 1024 * 1024
)
MAX_PACKAGE_DOWNLOAD_BYTES = positive_env_int(
    "FEATHERED_MAX_PACKAGE_DOWNLOAD_BYTES", 32 * 1024 * 1024 * 1024
)

__all__ = [
    "MAX_METADATA_DOWNLOAD_BYTES",
    "MAX_METADATA_EXPANDED_BYTES",
    "MAX_PACKAGE_DOWNLOAD_BYTES",
    "positive_env_int",
]
