"""Credential registration and log/bundle redaction.

Repository URLs are hostile/operator-controlled input and may carry credentials.
This module owns the process-wide redaction registry so configuration, transport,
and reporting code share one sink-independent policy.
"""
from __future__ import annotations

from collections import deque
import re
import threading
from typing import Set
import urllib.parse

import repository_transport as _transport

SENSITIVE_QUERY_KEYS = _transport.SENSITIVE_QUERY_KEYS


def active_sensitive_query_keys() -> Set[str]:
    """Built-in plus operator-declared query credential field names."""
    return _transport.registered_sensitive_query_keys()


# Secret values seen in configured repository URLs. Pattern matching alone is
# not enough: malformed exception text can carry a password without URL syntax.
_KNOWN_SECRETS: Set[str] = set()
_KNOWN_SECRET_ORDER: deque[str] = deque()
_KNOWN_SECRETS_LOCK = threading.RLock()
_MIN_GLOBAL_SECRET_LENGTH = 7
_MAX_KNOWN_SECRETS = 4096


def remember_secret(value: str) -> None:
    secret = str(value or "")
    if len(secret) < _MIN_GLOBAL_SECRET_LENGTH:
        return
    with _KNOWN_SECRETS_LOCK:
        if secret in _KNOWN_SECRETS:
            return
        _KNOWN_SECRETS.add(secret)
        _KNOWN_SECRET_ORDER.append(secret)
        while len(_KNOWN_SECRET_ORDER) > _MAX_KNOWN_SECRETS:
            _KNOWN_SECRETS.discard(_KNOWN_SECRET_ORDER.popleft())


def register_url_secrets(url: str) -> None:
    """Remember long URL credential values for context-free exception scrubbing."""
    text = str(url or "")
    if "://" not in text:
        return
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return
    if parsed.password:
        remember_secret(parsed.password)
    sensitive = active_sensitive_query_keys()
    for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in sensitive and value:
            remember_secret(value)


def redact_text(text: str) -> str:
    """Redact credentials anywhere in free text."""
    body = str(text)
    body = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@",
        lambda m: f"{m.group(1)}{m.group(2)}:REDACTED@",
        body,
    )
    body = re.sub(
        r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+)@",
        lambda m: f"{m.group(1)}REDACTED@",
        body,
    )
    sensitive = active_sensitive_query_keys()
    if sensitive:
        body = re.sub(
            r"(?i)\b(" + "|".join(re.escape(k) for k in sorted(sensitive)) + r")=([^&\s\"\']+)",
            lambda m: f"{m.group(1)}=REDACTED",
            body,
        )
    with _KNOWN_SECRETS_LOCK:
        secrets = tuple(_KNOWN_SECRETS)
    for secret in secrets:
        if secret in body:
            body = body.replace(secret, "REDACTED")
    return body


def redact_url(url: str) -> str:
    """Strip credentials from a URL before logging or bundle publication."""
    text = str(url or "")
    if "://" not in text:
        return text
    try:
        parsed = urllib.parse.urlsplit(text)
    except ValueError:
        return text
    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        name = userinfo.split(":", 1)[0]
        netloc = (
            f"{name}:REDACTED@{host}"
            if name and ":" in userinfo
            else f"REDACTED@{host}"
        )
    query = parsed.query
    if query:
        fields = []
        sensitive = active_sensitive_query_keys()
        for raw_field in query.split("&"):
            raw_key, _separator, _raw_value = raw_field.partition("=")
            try:
                key = urllib.parse.unquote_plus(raw_key).lower()
            except (UnicodeDecodeError, ValueError):
                key = raw_key.lower()
            if key in sensitive:
                fields.append(f"{raw_key}=REDACTED")
            else:
                fields.append(raw_field)
        query = "&".join(fields)
    return urllib.parse.urlunsplit(
        (parsed.scheme, netloc, parsed.path, query, parsed.fragment)
    )


# Compatibility spellings retained for callers that historically used the
# private core helpers.
_active_sensitive_query_keys = active_sensitive_query_keys
_remember_secret = remember_secret

__all__ = [
    "SENSITIVE_QUERY_KEYS",
    "active_sensitive_query_keys",
    "redact_text",
    "redact_url",
    "register_url_secrets",
]
