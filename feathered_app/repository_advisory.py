"""Display repository transport and configured signature policy without changing it."""
from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from artifact_verification import repository_verification_strategy
from repository_config import RepoSpec


def archive_keyring_state(repo: RepoSpec) -> tuple[str, str]:
    """Describe configuration; only a completed build can report verification."""
    if repository_verification_strategy(repo) == "skip-provenance":
        return ("Keyring bypassed" if repo.keyring else "Checks skipped", "open")
    if repo.keyring:
        return "Keyring configured", "digest"
    if repo.allow_unverified_index:
        return "Unverified allowed", "open"
    return "Digest only", "digest"


def http_repository_advice(repositories: Iterable[RepoSpec]) -> str:
    """Warn about participating HTTP sources without imposing a build policy."""
    plain = []
    for repo in repositories:
        try:
            if urlsplit(repo.url).scheme.lower() == "http":
                plain.append(repo)
        except ValueError:
            continue  # Source validation owns malformed URLs.
    if not plain:
        return ""
    devuan = any(repo.vendor_id == "devuan" for repo in plain)
    prefix = "Devuan's default repositories use HTTP. " if devuan else "Selected repositories use HTTP. "
    message = prefix + (
        "HTTP does not authenticate the server or encrypt downloads. Checksums from "
        "the same unauthenticated connection do not establish who published the files. "
        "Use a trusted archive keyring in Provenance and Keying to verify signed metadata "
        "and its package checksums. Obtain the keyring through a trusted channel. "
        "Signature verification authenticates content; it does not encrypt HTTP. "
        "You can continue without a keyring."
    )
    if any(repository_verification_strategy(repo) == "skip-provenance" for repo in plain):
        message += (
            " Skip upstream provenance checks bypasses configured keyrings too. "
            "Select Verify what is available or a stronger policy to use them."
        )
    return message
