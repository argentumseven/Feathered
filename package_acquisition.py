"""Package payload acquisition with bounded streaming and atomic publication."""
from __future__ import annotations

import shutil
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

import artifact_digests
import repository_transport as transport
from core_models import BuildOptions
from credential_redaction import redact_text, redact_url
from execution_reporter import Reporter
from package_transfer import copy_package_stream_bounded, package_download_limit
from repository_paths import repo_relative_url


@dataclass(frozen=True)
class AcquisitionServices:
    open_url: Callable[..., Any]
    verify_artifact: Callable[[Any, Path, BuildOptions, Reporter], bool]


def copy_or_download(
    pkg: Any,
    dest: Path,
    options: BuildOptions,
    reporter: Reporter,
    services: AcquisitionServices,
) -> None:
    """Acquire one package, verify it, then atomically publish it to ``dest``."""
    src = repo_relative_url(pkg.repo.normalized_url, pkg.location, pkg.repo)
    tmp = dest.with_suffix(dest.suffix + ".partial")
    for attempt in range(1, options.retries + 1):
        reporter.check_cancel()
        try:
            if tmp.exists():
                tmp.unlink()
            reporter.transfer(pkg.nevra, 0, int(getattr(pkg, "size", 0) or 0))
            parsed = urllib.parse.urlparse(src)
            if parsed.scheme == "file":
                local = Path(urllib.request.url2pathname(parsed.path))
                reporter.log(f"COPY {local} -> {dest.name}")
                limit, expected = package_download_limit(pkg)
                actual = local.stat().st_size
                if actual > limit:
                    raise RuntimeError(
                        f"{pkg.nevra}: local package is {actual:,} bytes, above the allowed "
                        f"{limit:,}-byte package limit"
                    )
                if expected and actual != expected:
                    raise RuntimeError(
                        f"{pkg.nevra}: local package size {actual:,} does not match repository "
                        f"metadata size {expected:,}"
                    )
                with local.open("rb") as source, tmp.open("wb") as target:
                    copy_package_stream_bounded(source, target, pkg, reporter, actual)
                shutil.copystat(local, tmp)
            else:
                reporter.log(f"DOWNLOAD {redact_url(src)}")
                with services.open_url(src, timeout=90, repo=pkg.repo) as response, tmp.open("wb") as handle:
                    declared = (
                        response.headers.get("Content-Length")
                        if hasattr(response, "headers")
                        else None
                    )
                    copy_package_stream_bounded(response, handle, pkg, reporter, declared)
            services.verify_artifact(pkg, tmp, options, reporter)
            artifact_digests.publish_payload(tmp, dest)
            return
        except Exception as exc:
            if tmp.exists():
                tmp.unlink()
            reporter.check_cancel()
            cert_advice = transport.certificate_failure_advice(exc, src)
            if cert_advice:
                raise RuntimeError(f"Failed {pkg.nevra}: {cert_advice}") from exc
            if attempt == options.retries:
                raise RuntimeError(f"Failed {pkg.nevra}: {exc}") from exc
            reporter.log(
                redact_text(
                    f"Healing download failure for {pkg.nevra}: {exc}; "
                    f"retry {attempt + 1}/{options.retries}"
                )
            )
            time.sleep(min(2 ** (attempt - 1), 5))
