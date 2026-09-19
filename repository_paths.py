"""Repository-relative path confinement and filesystem URL helpers."""
from __future__ import annotations

import posixpath
from pathlib import Path
from typing import Optional
import urllib.parse
import urllib.request

from credential_redaction import redact_url
from repository_config import RepoSpec
import repository_transport as _transport


def repo_relative_url(base: str, location: str, repo: Optional[RepoSpec] = None) -> str:
    """Resolve a package location against its repository, refusing to escape it.

    Package locations come from repository metadata, which is exactly the thing
    an attacker controls when a mirror is compromised. urljoin() happily honours
    an absolute URL, a protocol-relative one, or enough ../ segments to leave
    the repository -- so a hostile index could redirect a package fetch to
    another host, or to a file: path on the build machine. A location must be a
    path underneath the repository root, and anything else is refused.
    """
    text = (location or "").strip()
    if not text:
        raise RuntimeError("Repository metadata supplied an empty package location")
    parsed = urllib.parse.urlsplit(text)
    if parsed.scheme or parsed.netloc or text.startswith("//"):
        raise RuntimeError(
            f"Repository metadata supplies an absolute package location ({redact_url(text)}). "
            "Package locations must be relative to the repository; refusing to fetch from a "
            "different origin than the repository that advertised it.")
    # Normalize the repository *path* rather than appending '/' to the raw URL;
    # appending after '?token=...' corrupts query-authenticated repository URLs.
    base_parts = urllib.parse.urlsplit(base)
    root_path = (base_parts.path or "/").rstrip("/") + "/"
    root = urllib.parse.urlunsplit(
        (base_parts.scheme, base_parts.netloc, root_path, base_parts.query, base_parts.fragment))
    joined = urllib.parse.urljoin(root, text)
    # Compare on the normalised path so ../ traversal cannot climb out.
    root_parts = urllib.parse.urlsplit(root)
    joined_parts = urllib.parse.urlsplit(joined)
    # validate decoded path semantics too.
    # Reverse proxies and HTTP servers commonly decode %2e/%2f before routing;
    # checking only the encoded string would let %2e%2e escape the repository
    # even though literal ../ is refused. Decode repeatedly for validation only
    # (the original URL is still returned/fetched).
    def fully_decode_path(path: str) -> str:
        decoded = path
        for _ in range(16):
            try:
                next_value = urllib.parse.unquote(decoded, errors="strict")
            except UnicodeDecodeError as exc:
                raise RuntimeError(
                    "Repository metadata contains invalid percent-encoded path bytes; "
                    "refusing ambiguous repository traversal semantics.") from exc
            if next_value == decoded:
                return decoded
            decoded = next_value
        raise RuntimeError(
            "Repository metadata path encoding is nested too deeply to canonicalize safely; "
            "refusing ambiguous repository traversal semantics.")

    decoded_root = fully_decode_path(root_parts.path)
    decoded_joined = fully_decode_path(joined_parts.path)
    if "\x00" in decoded_root or "\x00" in decoded_joined:
        raise RuntimeError(
            "Repository metadata contains a NUL byte in a decoded path; refusing ambiguous "
            "repository traversal semantics.")
    if "\\" in decoded_joined:
        raise RuntimeError(
            f"Repository metadata supplies a location with backslash path separators "
            f"({redact_url(text)}). Refusing ambiguous repository traversal semantics.")
    if (joined_parts.scheme, joined_parts.netloc) != (root_parts.scheme, root_parts.netloc) \
            or not posixpath.normpath(decoded_joined).startswith(
                posixpath.normpath(decoded_root).rstrip("/") + "/"):
        raise RuntimeError(
            f"Repository metadata supplies a package location that escapes the repository "
            f"({redact_url(text)}). Refusing to fetch outside {redact_url(root)}.")
    return _transport.inherit_sensitive_query_credentials(base, joined, repo)

def path_to_file_url(path) -> str:
    """Convert a filesystem path to a file: URL that survives round-tripping.

    Path.as_uri() is wrong for Windows UNC paths: it renders
    \\\\server\\share\\x as file://server/share/x, putting the server in the URL
    *host* field. Every consumer then parses it back with url2pathname(path),
    which sees only /share/x and silently drops the server -- so an SMB mirror
    resolves to a non-existent local directory and reports "not found".

    pathname2url encodes UNC as file:////server/share/x (empty host, path
    beginning //server), which url2pathname reverses correctly.
    """
    text = str(path)
    return "file:" + urllib.request.pathname2url(text)

def file_url_to_path(url: str) -> Path:
    """Inverse of path_to_file_url for local and UNC file: URLs."""
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc and parsed.netloc.lower() not in {"", "localhost"}:
        # Tolerate the legacy file://server/share form written by as_uri().
        return Path(urllib.request.url2pathname("//" + parsed.netloc + parsed.path))
    return Path(urllib.request.url2pathname(parsed.path))

def human_size(value: float) -> str:
    """Byte count for humans; shared so progress text reads the same everywhere."""
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"

__all__ = [
    "file_url_to_path",
    "human_size",
    "path_to_file_url",
    "repo_relative_url",
]
