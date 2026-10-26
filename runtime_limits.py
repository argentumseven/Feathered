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

# Expanded-byte ceilings alone do not bound parser/process memory.  These
# aggregate limits cap the number of Python objects and retained text a hostile
# repository can induce after decompression while remaining well above normal
# distribution repository sizes.
MAX_METADATA_PACKAGE_RECORDS = positive_env_int(
    "FEATHERED_MAX_METADATA_PACKAGE_RECORDS", 250_000
)
MAX_METADATA_RELATIONSHIP_RECORDS = positive_env_int(
    "FEATHERED_MAX_METADATA_RELATIONSHIP_RECORDS", 4_000_000
)
# RPM primary.xml carries many more explicit provides/requires records than
# comparable APT indexes.  The live AlmaLinux 10.2 BaseOS index contains
# 4,232,225 such entries for x86_64/noarch, so the former 4m cross-format
# default rejected an otherwise bounded repository before resolution.
# Keep APT's existing ceiling and give RPM a separate finite 5m default.
MAX_RPM_METADATA_RELATIONSHIP_RECORDS = positive_env_int(
    "FEATHERED_MAX_RPM_METADATA_RELATIONSHIP_RECORDS", 5_000_000
)
MAX_METADATA_FILE_ENTRIES = positive_env_int(
    "FEATHERED_MAX_METADATA_FILE_ENTRIES", 4_000_000
)
MAX_RETAINED_METADATA_CHARS = positive_env_int(
    "FEATHERED_MAX_RETAINED_METADATA_CHARS", 128 * 1024 * 1024
)

__all__ = [
    "MAX_METADATA_DOWNLOAD_BYTES",
    "MAX_METADATA_EXPANDED_BYTES",
    "MAX_METADATA_FILE_ENTRIES",
    "MAX_METADATA_PACKAGE_RECORDS",
    "MAX_METADATA_RELATIONSHIP_RECORDS",
    "MAX_RPM_METADATA_RELATIONSHIP_RECORDS",
    "MAX_PACKAGE_DOWNLOAD_BYTES",
    "MAX_RETAINED_METADATA_CHARS",
    "positive_env_int",
]
