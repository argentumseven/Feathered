"""Digest policy for repository metadata.

Repository indexes are hostile input and may nominate their own digest
algorithm.  This module centralizes the fail-closed allowlist used for those
metadata hashes so transport, repository loading, and supplemental metadata
all apply the same policy.
"""
from __future__ import annotations

import hashlib
from typing import IO

STRONG_HASHES = {"sha256", "sha384", "sha512", "sha3_256", "sha3_512"}
_HASH_ALIASES = {"sha-256": "sha256", "sha-384": "sha384", "sha-512": "sha512"}
WEAK_HASHES = {"md5", "sha1", "sha"}


def normalize_hash_name(algorithm: str) -> str:
    algo = (algorithm or "sha256").strip().lower().replace("-", "_")
    return _HASH_ALIASES.get(algorithm.strip().lower(), algo)


def hash_bytes(data: bytes, algorithm: str) -> str:
    algo = normalize_hash_name(algorithm)
    if algo in WEAK_HASHES:
        raise RuntimeError(
            f"Repository metadata requests the {algo} digest, which is not collision resistant. "
            "Refusing to verify with it; use a repository that publishes SHA-256 or stronger."
        )
    if algo not in STRONG_HASHES:
        raise RuntimeError(f"Unsupported metadata digest algorithm: {algorithm!r}")
    digest = hashlib.new(algo)
    digest.update(data)
    return digest.hexdigest()


def hash_stream(stream: IO[bytes], algorithm: str) -> str:
    """Hash a rewindable metadata stream without materializing it as bytes."""
    algo = normalize_hash_name(algorithm)
    if algo in WEAK_HASHES:
        raise RuntimeError(
            f"Repository metadata requests the {algo} digest, which is not collision resistant. "
            "Refusing to verify with it; use a repository that publishes SHA-256 or stronger."
        )
    if algo not in STRONG_HASHES:
        raise RuntimeError(f"Unsupported metadata digest algorithm: {algorithm!r}")
    digest = hashlib.new(algo)
    stream.seek(0)
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
    stream.seek(0)
    return digest.hexdigest()
