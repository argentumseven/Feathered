"""Bounded observation of available minor repositories, without a release list."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import tempfile
from urllib.error import HTTPError
from urllib.request import Request, urlopen

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ProbeResult:
    status: Literal['available', 'absent', 'indeterminate']
    reason: str = ''
    observed_at: str = field(default_factory=_now)


def probe_repository(url: str, opener: Callable[..., Any] = urlopen) -> ProbeResult:
    for method in ('HEAD', 'GET'):
        try:
            request = Request(url, method=method, headers={'Range': 'bytes=0-0'} if method == 'GET' else {})
            with opener(request, timeout=3) as response:
                if 200 <= response.status < 300:
                    return ProbeResult('available')
                return ProbeResult('indeterminate', f'HTTP {response.status}')
        except HTTPError as exc:
            if exc.code in (404, 410):
                return ProbeResult('absent', f'HTTP {exc.code}')
            if exc.code not in (405, 501):
                return ProbeResult('indeterminate', f'HTTP {exc.code}')
        except Exception as exc:
            reason = type(exc).__name__
            if method == 'GET':
                return ProbeResult('indeterminate', reason)
    return ProbeResult('indeterminate', 'Repository probe did not produce an authoritative answer')


@dataclass(frozen=True)
class Observation:
    versions: tuple[str, ...]
    observed_at: str
    source: str
    error: str = ''
    checks: tuple[tuple[str, ProbeResult], ...] = ()


def discover(family: str, probe: Callable[[str], bool | ProbeResult],
             progress: Callable[[Observation], None] | None = None,
             candidates: tuple[str, ...] | None = None) -> Observation:
    suffix = 'deb/Release' if family == 'deb' else 'rpm/repodata/repomd.xml'
    source = 'https://pkgs.k8s.io/core:/stable:/v1.{n}/' + suffix
    found: list[int] = []
    misses = 0
    checks: dict[str, ProbeResult] = {}
    def check(minor: int) -> ProbeResult:
        try:
            result = probe(source.format(n=minor))
            return result if isinstance(result, ProbeResult) else ProbeResult('available' if result else 'absent')
        except Exception as exc:
            return ProbeResult('indeterminate', type(exc).__name__)

    def observation(error: str = '') -> Observation:
        uncertain = [minor for minor, result in checks.items() if result.status == 'indeterminate']
        if uncertain:
            error = 'Repository checks incomplete for ' + ', '.join(uncertain) + '; availability is unconfirmed.'
        return Observation(tuple(f'1.{n}' for n in sorted(found, reverse=True)),
                           _now(), source, error, tuple(checks.items()))

    # Probe small bounded batches concurrently. Publish actual discoveries as
    # they arrive, while retaining the ordered three-miss stopping rule.
    with ThreadPoolExecutor(max_workers=8) as pool:
        # Explicit upstream candidates can extend beyond the old probing cap.
        # Gaps no longer end the scan when the release is known to exist.
        from k8s_version import parse
        minors = list(dict.fromkeys(parse(v).minor for v in candidates)) if candidates is not None else list(range(24, 84))
        for start in range(0, len(minors), 8):
            futures = {pool.submit(check, n): n for n in minors[start:start + 8]}
            results = {}
            for future in as_completed(futures):
                minor = futures[future]
                results[minor] = future.result()
                checks[f'1.{minor}'] = results[minor]
                if results[minor].status == 'available':
                    found.append(minor)
                    if progress:
                        progress(observation())
            for minor in sorted(results):
                misses = misses + 1 if results[minor].status == 'absent' else 0
                if candidates is None and misses == 3:
                    return observation('' if found else 'Minor repository discovery failed. Enter a Kubernetes minor explicitly; availability is not confirmed.')
    return observation(
        '' if found else 'Minor repository discovery failed. Enter a Kubernetes minor explicitly; availability is not confirmed.')


def retain(previous: Observation | None, current: Observation) -> Observation:
    if previous is None:
        return current
    absent = {minor for minor, result in current.checks if result.status == 'absent'}
    retained = set(previous.versions) - set(current.versions) - absent
    if not retained:
        return current
    from k8s_version import parse
    versions = tuple(sorted(set(current.versions) | retained, key=lambda v: parse(v).minor, reverse=True))
    # This conservative timestamp never labels retained entries freshly checked.
    return replace(current, versions=versions, observed_at=min(previous.observed_at, current.observed_at),
                   error=(current.error + ' ' if current.error else '') +
                         'Retaining previously observed repositories whose availability is unconfirmed.')


def save(path: Path, observation: Observation) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    name = ''
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as f:
            name = f.name
            json.dump(asdict(observation), f)
        Path(name).replace(path)
    finally:
        if name:
            Path(name).unlink(missing_ok=True)


def read(path: Path) -> Observation | None:
    try:
        if path.stat().st_size > 512 * 1024:
            return None
        data = json.loads(path.read_text(encoding='utf-8'))
        from k8s_version import parse
        if not isinstance(data['versions'], list):
            return None
        versions = tuple(parse(v).line for v in data['versions'])
        checks = tuple((parse(minor).line, ProbeResult(**result)) for minor, result in data.get('checks', ()))
        if any(result.status not in ('available', 'absent', 'indeterminate') for _, result in checks):
            return None
        return Observation(versions, str(data['observed_at']), str(data['source']), str(data.get('error', '')), checks)
    except (OSError, KeyError, TypeError, ValueError):
        return None
