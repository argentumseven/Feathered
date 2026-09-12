"""Bounded observation of available minor repositories, without a release list."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

@dataclass(frozen=True)
class Observation:
    versions: tuple[str, ...]
    observed_at: str
    source: str
    error: str = ''


def discover(family: str, probe: Callable[[str], bool],
             progress: Callable[[Observation], None] | None = None,
             candidates: tuple[str, ...] | None = None) -> Observation:
    suffix = 'deb/Release' if family == 'deb' else 'rpm/repodata/repomd.xml'
    source = 'https://pkgs.k8s.io/core:/stable:/v1.{n}/' + suffix
    found: list[int] = []
    misses = 0
    def check(minor: int) -> bool:
        try:
            return probe(source.format(n=minor))
        except Exception:
            return False

    def observation(error: str = '') -> Observation:
        return Observation(tuple(f'1.{n}' for n in sorted(found, reverse=True)),
                           datetime.now(timezone.utc).isoformat(), source, error)

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
                if results[minor]:
                    found.append(minor)
                    if progress:
                        progress(observation())
            for minor in sorted(results):
                misses = 0 if results[minor] else misses + 1
                if candidates is None and misses == 3:
                    return observation('' if found else 'Minor repository discovery failed. Enter a Kubernetes minor explicitly; availability is not confirmed.')
    return observation(
        '' if found else 'Minor repository discovery failed. Enter a Kubernetes minor explicitly; availability is not confirmed.')


def save(path: Path, observation: Observation) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(asdict(observation)), encoding='utf-8')
    temporary.replace(path)


def read(path: Path) -> Observation | None:
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        from k8s_version import parse
        versions = tuple(parse(v).line for v in data['versions'])
        return Observation(versions, str(data['observed_at']), str(data['source']), str(data.get('error', '')))
    except (OSError, KeyError, TypeError, ValueError):
        return None
