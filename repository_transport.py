from __future__ import annotations

import ssl
import tempfile
import time
import urllib.parse
import urllib.request
from typing import Callable, ContextManager, Dict, Optional, Protocol, Set, TypeVar


class TransportReporter(Protocol):
    def log(self, message: str, /) -> None: ...
    def check_cancel(self) -> None: ...


class ByteResponse(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


RepositoryT = TypeVar("RepositoryT")


SENSITIVE_QUERY_KEYS = {
    "token", "access_token", "api_key", "apikey", "key", "password",
    "secret", "sig", "signature", "auth",
    # Common signed-URL credential fields.  These values are bearer material
    # even when the query parameter name does not contain a generic "token".
    "x-amz-credential", "x-amz-signature", "x-amz-security-token",
    "x-goog-credential", "x-goog-signature", "x-goog-security-token",
}

# Generic repository bearer tokens can be inherited to same-origin child URLs.
# Cloud-provider signed URLs are path/query bound and must not be copied to a
# different child path: doing so would both leak bearer material and produce an
# invalid signature.
INHERITABLE_QUERY_CREDENTIAL_KEYS = {
    "token", "access_token", "api_key", "apikey", "key", "password",
    "secret", "sig", "signature", "auth",
}


def effective_origin(url: str) -> str:
    parts = urllib.parse.urlsplit(str(url or ""))
    scheme = (parts.scheme or "").lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"} or not host:
        return ""
    port = parts.port or (443 if scheme == "https" else 80)
    return f"{scheme}://{host}:{port}"


def effective_hostname(url: str) -> str:
    parts = urllib.parse.urlsplit(str(url or ""))
    return (parts.hostname or "").lower().rstrip(".")


def sensitive_query_parts(url: str) -> Dict[str, str]:
    """Return configured credential query fragments keyed by decoded name."""
    try:
        query = urllib.parse.urlsplit(str(url or "")).query
    except ValueError:
        return {}
    out: Dict[str, str] = {}
    for fragment in query.split("&"):
        if not fragment:
            continue
        raw_key = fragment.split("=", 1)[0]
        key = urllib.parse.unquote_plus(raw_key).strip().lower()
        if key in SENSITIVE_QUERY_KEYS:
            out[key] = fragment
    return out


def url_has_endpoint_credentials(url: str) -> bool:
    try:
        parts = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return False
    return bool(parts.username or parts.password or sensitive_query_parts(url))


def repo_has_endpoint_credentials(repo: Optional[object]) -> bool:
    if repo is None:
        return False
    return bool(
        getattr(repo, "client_cert", "")
        or getattr(repo, "client_key", "")
        or url_has_endpoint_credentials(getattr(repo, "url", ""))
    )


def credential_redirect_allow_origins(repo: Optional[object]) -> Set[str]:
    allowed: Set[str] = set()
    if repo is None:
        return allowed
    for value in getattr(repo, "redirect_allow_origins", []) or []:
        origin = effective_origin(str(value or ""))
        if origin:
            allowed.add(origin)
    return allowed


def inherit_sensitive_query_credentials(base: str, child: str) -> str:
    """Carry recognized repository query credentials to same-origin children."""
    inherited = {
        key: fragment for key, fragment in sensitive_query_parts(base).items()
        if key in INHERITABLE_QUERY_CREDENTIAL_KEYS
    }
    if not inherited:
        return child
    if effective_origin(base) != effective_origin(child):
        return child
    parts = urllib.parse.urlsplit(child)
    kept = []
    for fragment in parts.query.split("&"):
        if not fragment:
            continue
        raw_key = fragment.split("=", 1)[0]
        key = urllib.parse.unquote_plus(raw_key).strip().lower()
        if key in inherited:
            continue
        kept.append(fragment)
    query = "&".join(list(inherited.values()) + kept)
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def url_join(base: str, href: str) -> str:
    return inherit_sensitive_query_credentials(base, urllib.parse.urljoin(base, href))


def ssl_context(repo: Optional[object] = None):
    if repo is None or not (
        getattr(repo, "client_cert", "")
        or getattr(repo, "client_key", "")
        or getattr(repo, "ca_cert", "")
    ):
        return None
    client_cert = getattr(repo, "client_cert", "")
    client_key = getattr(repo, "client_key", "")
    if bool(client_cert) != bool(client_key):
        raise RuntimeError(f"{getattr(repo, 'name', 'Repository')}: both client certificate and client key are required")
    context = ssl.create_default_context(cafile=getattr(repo, "ca_cert", "") or None)
    if client_cert and client_key:
        context.load_cert_chain(client_cert, client_key)
    return context


class RepositoryRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Origin-confine redirects for repositories carrying endpoint credentials."""

    def __init__(self, repo: Optional[object]):
        super().__init__()
        self.repo = repo

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        current_scheme = (urllib.parse.urlsplit(req.full_url).scheme or "").lower()
        target_scheme = (urllib.parse.urlsplit(target).scheme or "").lower()
        if current_scheme == "https" and target_scheme != "https":
            raise RuntimeError(
                f"Repository redirect from HTTPS to {target_scheme or 'a non-HTTP(S) URL'} is not allowed. "
                "Configure an HTTP repository explicitly if plaintext transport is intended.")
        if repo_has_endpoint_credentials(self.repo):
            current_origin = effective_origin(req.full_url)
            target_origin = effective_origin(target)
            allow = credential_redirect_allow_origins(self.repo)
            if not current_origin or not target_origin:
                raise RuntimeError(
                    "Credentialed repository redirect does not remain on an HTTP(S) origin; "
                    "refusing to forward repository authentication")
            if target_origin != current_origin and target_origin not in allow:
                raise RuntimeError(
                    f"Credentialed repository redirect from {current_origin} to {target_origin} "
                    "is not allowed. Keep redirects same-origin or explicitly allow the vendor CDN origin.")
            if target_origin == current_origin:
                target = inherit_sensitive_query_credentials(req.full_url, target)
        return super().redirect_request(req, fp, code, msg, headers, target)


def record_effective_origin(repo: Optional[object], final_url: str) -> None:
    if repo is None:
        return
    origin = effective_origin(final_url)
    if not origin:
        return
    origins = getattr(repo, "_effective_origins", None)
    if origins is None:
        origins = set()
        setattr(repo, "_effective_origins", origins)
    origins.add(origin)
    host = effective_hostname(final_url)
    if host:
        hosts = getattr(repo, "_effective_hosts", None)
        if hosts is None:
            hosts = set()
            setattr(repo, "_effective_hosts", hosts)
        hosts.add(host)


def _request(url: str, user_agent: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"User-Agent": user_agent})


def open_url(url: str, timeout: int, repo: Optional[object] = None, *, user_agent: str):
    """Open a repository URL under Feathered's credential and evidence policy."""
    context = ssl_context(repo)
    # Always install Feathered's redirect handler.  Redirect transport policy
    # (notably HTTPS -> HTTP downgrade refusal) applies even when the repository
    # carries no endpoint credentials.
    handlers: list[urllib.request.BaseHandler] = [RepositoryRedirectHandler(repo)]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    response = opener.open(_request(url, user_agent), timeout=timeout)

    note_successful_fetch(url)
    try:
        final_url = response.geturl()
    except AttributeError as exc:
        response.close()
        raise RuntimeError(
            "Repository response does not expose its final URL; origin cannot be verified") from exc
    initial_scheme = (urllib.parse.urlsplit(url).scheme or "").lower()
    final_scheme = (urllib.parse.urlsplit(final_url).scheme or "").lower()
    if initial_scheme == "https" and final_scheme != "https":
        response.close()
        raise RuntimeError(
            f"Repository request configured as HTTPS ended at {final_scheme or 'a non-HTTP(S) URL'}; "
            "refusing a transport-security downgrade")
    record_effective_origin(repo, final_url)

    distinct_from = str(getattr(repo, "_evidence_distinct_from", "") or "") if repo else ""
    if distinct_from:
        configured_origin = effective_origin(distinct_from)
        configured_host = effective_hostname(distinct_from)
        final_origin = effective_origin(final_url)
        final_host = effective_hostname(final_url)
        acquisition_effective = set(
            getattr(repo, "_evidence_distinct_effective_origins", set()) or set())
        acquisition_hosts = set(
            getattr(repo, "_evidence_distinct_effective_hosts", set()) or set())
        forbidden = ({configured_origin} if configured_origin else set()) | acquisition_effective
        forbidden_hosts = ({configured_host} if configured_host else set()) | acquisition_hosts
        if not final_origin:
            response.close()
            raise RuntimeError(
                "Evidence response did not end at an HTTP(S) origin; independence cannot be established")
        if final_origin in forbidden or final_host in forbidden_hosts:
            response.close()
            raise RuntimeError(
                f"Evidence mirror redirected to acquisition host/effective endpoint {final_origin}; "
                "the Source Bond is not endpoint-distinct")
    return response


# Hosts that have already failed certificate validation this session. Two
# unrelated origins failing the same way is near-proof the fault is local
# (clock or trust store), not a coincidence of two broken mirrors.
_CERT_FAILED_HOSTS: Set[str] = set()
_TLS_SUCCESS_HOSTS: Set[str] = set()


def note_successful_fetch(url: str) -> None:
    """Record an HTTPS origin that validated normally this session.

    One success proves the local clock and trust store are fine, which rules
    out the whole class of "your computer is wrong" explanations for another
    host's certificate failure."""
    parts = urllib.parse.urlsplit(str(url or ""))
    if (parts.scheme or "").lower() == "https":
        host = effective_hostname(url)
        if host:
            _TLS_SUCCESS_HOSTS.add(host)


def note_certificate_failure(url: str) -> int:
    host = effective_hostname(url)
    if host:
        _CERT_FAILED_HOSTS.add(host)
    return len(_CERT_FAILED_HOSTS)


def certificate_failure_advice(exc: BaseException, url: str = "") -> str:
    """Actionable text for a TLS certificate verification failure, or "".

    Certificate validation failures are not transient: retrying in seconds
    cannot fix an expired or untrusted certificate, and the operator needs to
    know the concrete remedies rather than a bare OpenSSL error."""
    seen = set()
    node: Optional[BaseException] = exc
    cert_error: Optional[ssl.SSLCertVerificationError] = None
    while node is not None and id(node) not in seen:
        seen.add(id(node))
        if isinstance(node, ssl.SSLCertVerificationError):
            cert_error = node
            break
        reason = getattr(node, "reason", None)
        node = reason if isinstance(reason, BaseException) else (node.__cause__ or node.__context__)
    if cert_error is None:
        return ""
    detail = str(getattr(cert_error, "verify_message", "") or cert_error)
    expired = "expired" in detail.lower()
    distinct_hosts = note_certificate_failure(url) if url else 0
    advice = ("The server's TLS certificate failed validation"
              + (f" ({detail})" if detail else "") + ". ")
    if _TLS_SUCCESS_HOSTS:
        example = sorted(_TLS_SUCCESS_HOSTS)[0]
        advice += ("This computer's clock and certificate store are demonstrably fine: %s "
                   "validated normally in this same session. The fault is this mirror. Edit "
                   "the repository and point it at another mirror of the same archive. "
                   % example)
    elif distinct_hosts >= 2:
        advice += ("NOTE: %d different hosts have now failed certificate validation the same "
                   "way in this session. If other HTTPS sites work in a browser, these mirrors "
                   "are simply misconfigured; otherwise check this computer's date/time and "
                   "root-certificate updates. " % distinct_hosts)
    elif expired:
        advice += ("Either this mirror is serving an expired certificate or this computer's "
                   "date/time is wrong. Check the system clock first. ")
    else:
        advice += ("Either this mirror's certificate/chain is broken or this computer's "
                   "trust store or clock is wrong. Check the system date first. ")
    advice += ("If the clock is correct, the mirror itself is at fault: edit this repository "
               "and point it at a different mirror of the same archive (geo-routed hostnames "
               "such as geo.mirror.pkgbuild.com pick a nearby mirror for you, and that specific "
               "mirror may be misconfigured even when others are healthy). For a private "
               "repository with an internal CA, configure its CA certificate on the repository row.")
    return advice


def fetch_bytes(
    url: str,
    reporter: TransportReporter,
    *,
    retries: int = 3,
    timeout: int = 45,
    repo: Optional[RepositoryT] = None,
    max_bytes: Optional[int] = None,
    open_url_fn: Callable[[str, int, Optional[RepositoryT]], ContextManager[ByteResponse]],
    redact_url_fn: Callable[[str], str],
) -> bytes:
    """Fetch bounded bytes using an injected opener and reporter.

    The injected opener keeps transport directly unit-testable while allowing
    core.py to retain its compatibility monkeypatch seam during decomposition.
    """
    last: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        reporter.check_cancel()
        try:
            suffix = f" (attempt {attempt}/{retries})" if attempt > 1 else ""
            client_cert: object = getattr(repo, "client_cert", "") if repo else ""
            auth = " [client-certificate auth]" if client_cert else ""
            reporter.log(f"GET {redact_url_fn(url)}{auth}{suffix}")
            with open_url_fn(url, timeout, repo) as response:
                if max_bytes is not None:
                    declared = response.headers.get("Content-Length") if hasattr(response, "headers") else None
                    try:
                        declared_size = int(declared) if declared is not None else None
                    except (TypeError, ValueError):
                        declared_size = None
                    if declared_size is not None and declared_size > max_bytes:
                        raise RuntimeError(
                            f"Repository response is {declared_size:,} bytes, above Feathered's "
                            f"{max_bytes:,}-byte metadata limit")
                total = 0
                spool_threshold = 64 * 1024 * 1024
                if max_bytes is not None:
                    spool_threshold = min(spool_threshold, max_bytes)
                with tempfile.SpooledTemporaryFile(max_size=max(1, spool_threshold)) as spool:
                    while True:
                        reporter.check_cancel()
                        chunk = response.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if max_bytes is not None and total > max_bytes:
                            raise RuntimeError(
                                f"Repository response exceeded Feathered's {max_bytes:,}-byte metadata limit")
                        spool.write(chunk)
                    spool.seek(0)
                    return spool.read()
        except Exception as exc:
            # A cancellation raised mid-download (reporter.check_cancel inside
            # the chunk loop) must propagate as a cancellation, not be retried
            # or reported as a fetch failure on the final attempt.  Re-checking
            # here re-raises the reporter's own cancellation type without this
            # module needing to import it.
            reporter.check_cancel()
            # Certificate validation failures are deterministic: an expired or
            # untrusted certificate will not become valid on the next attempt,
            # so retrying only delays the operator and buries the real remedy.
            advice = certificate_failure_advice(exc, url)
            if advice:
                raise RuntimeError(
                    f"Could not fetch {redact_url_fn(url)}: {advice}") from exc
            last = exc
            if attempt < retries:
                reporter.log(f"Fetch failed: {exc}. Healing with retry...")
                time.sleep(min(2 ** (attempt - 1), 5))
    raise RuntimeError(f"Could not fetch {redact_url_fn(url)}: {last}")
