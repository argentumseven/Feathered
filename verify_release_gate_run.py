"""Require every platform test gate for the exact tagged source before recovery publication."""
from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request
from typing import Any

REQUIRED_JOBS = frozenset({
    'Windows source + mount gate',
    'Native package-manager conformance / apt',
    'Native package-manager conformance / dnf',
    'Native package-manager conformance / pacman',
    'Static analysis / mypy + ruff',
    *{f'Installed Linux GUI and CLI / installed-client ({image})'
      for image in ('ubuntu:22.04', 'ubuntu:24.04', 'debian:12')},
})


def verify(run: dict[str, Any], jobs: list[dict[str, Any]], commit: str) -> None:
    if (re.fullmatch(r'[0-9a-f]{40}', commit) is None or run.get('head_sha') != commit
            or run.get('path') != '.github/workflows/windows-release.yml'
            or run.get('event') != 'push' or run.get('status') != 'completed'):
        raise RuntimeError('Gate run is not a completed release workflow for the exact source commit')
    for name in sorted(REQUIRED_JOBS):
        matches = [job for job in jobs if job.get('name') == name]
        if (len(matches) != 1 or matches[0].get('status') != 'completed'
                or matches[0].get('conclusion') != 'success'
                or matches[0].get('head_sha') != commit):
            raise RuntimeError(f'Required source gate did not pass exactly once: {name}')


def fetch(repo: str, run_id: int, token: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) is None or run_id <= 0:
        raise RuntimeError('Invalid repository or gate run ID')
    base = f'https://api.github.com/repos/{repo}/actions/runs/{run_id}'

    def get(url: str) -> Any:
        request = urllib.request.Request(url, headers={
            'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
        })
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)

    run = get(base)
    jobs: list[dict[str, Any]] = []
    for page in range(1, 11):
        result = get(f'{base}/jobs?filter=latest&per_page=100&page={page}')
        rows = result['jobs']
        jobs.extend(rows)
        if len(rows) < 100:
            return run, jobs
    raise RuntimeError('Gate job listing exceeded the pagination limit')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', required=True)
    parser.add_argument('--run-id', required=True, type=int)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    token = os.environ.get('GH_TOKEN', '')
    if not token:
        raise RuntimeError('GH_TOKEN is required to inspect release gate results')
    run, jobs = fetch(args.repo, args.run_id, token)
    verify(run, jobs, args.commit)
    print(f'All {len(REQUIRED_JOBS)} required platform jobs passed for {args.commit} (run {args.run_id}).')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f'::error::{exc}')
        raise SystemExit(1) from exc
