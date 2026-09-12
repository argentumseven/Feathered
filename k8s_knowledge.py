"""Refresh release facts from Kubernetes; remote prose never becomes policy code."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import tempfile
from typing import Callable
from urllib.request import Request, urlopen

ROOT = 'https://raw.githubusercontent.com/kubernetes/website/main/'
SCHEDULE = ROOT + 'data/releases/schedule.yaml'
HISTORY = ROOT + 'data/releases/eol.yaml'
SKEW = ROOT + 'content/en/releases/version-skew-policy.md'
KUBEADM = ROOT + 'content/en/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm.md'
URLS = (SCHEDULE, HISTORY, SKEW, KUBEADM)
MAX_BYTES = 512 * 1024
TTL_SECONDS = 6 * 60 * 60
SEED_PATH = Path(__file__).with_name('k8s_knowledge_seed.json')

@dataclass(frozen=True)
class Release:
    minor: str
    end_of_life: str

@dataclass(frozen=True)
class Evidence:
    url: str
    sha256: str
    observed_at: str
    digest_scope: str = 'response-bytes'

@dataclass(frozen=True)
class Knowledge:
    releases: tuple[Release, ...] = ()
    sources: tuple[Evidence, ...] = ()
    error: str = ''
    changed_policies: tuple[str, ...] = ()

    @property
    def repository_candidates(self) -> tuple[str, ...]:
        # pkgs.k8s.io starts at 1.24, independently of valid cluster versions.
        return tuple(r.minor for r in self.releases if int(r.minor.split('.')[1]) >= 24)


def fetch(url: str) -> bytes:
    if url not in URLS:
        raise ValueError('Unrecognised upstream source')
    with urlopen(Request(url, headers={'User-Agent': 'Feathered-release-knowledge/1'}), timeout=4) as response:
        if response.geturl() != url:
            raise ValueError('Unexpected upstream source redirect')
        body = response.read(MAX_BYTES + 1)
    if not body or len(body) > MAX_BYTES:
        raise ValueError('Empty or oversized upstream document')
    return body


def _rows(body: bytes, key: str) -> list:
    import yaml
    class NoAliases(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise ValueError('YAML aliases are not accepted')
            return super().compose_node(parent, index)
    if len(body) > MAX_BYTES:
        raise ValueError('Oversized release feed')
    value = yaml.load(body, Loader=NoAliases)
    rows = value.get(key) if isinstance(value, dict) else None
    if not isinstance(rows, list) or not rows or len(rows) > 512:
        raise ValueError('Unrecognised or empty release feed')
    return rows


def parse_releases(schedule: bytes, history: bytes, today: date | None = None) -> tuple[Release, ...]:
    today = today or date.today()
    found: dict[str, Release] = {}
    for body, key in ((history, 'branches'), (schedule, 'schedules')):
        for row in _rows(body, key):
            if not isinstance(row, dict) or not isinstance(row.get('release'), str):
                raise ValueError('Invalid release record')
            minor = row['release']
            if not re.fullmatch(r'1\.(?:0|[1-9]\d*)', minor):
                raise ValueError('Unrecognised release version; adapter needs review')
            eol = date.fromisoformat(str(row['endOfLifeDate'])).isoformat()
            if key == 'schedules' and date.fromisoformat(str(row['releaseDate'])) > today:
                continue
            found[minor] = Release(minor, eol)
    if not found:
        raise ValueError('No published releases in upstream data')
    return tuple(sorted(found.values(), key=lambda r: int(r.minor.split('.')[1]), reverse=True))


def read(path: Path) -> Knowledge | None:
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('schema') != 1:
            return None
        releases = tuple(Release(**r) for r in data['releases'])
        sources = tuple(Evidence(**s) for s in data['sources'])
        if not releases or len(releases) > 512 or len({r.minor for r in releases}) != len(releases):
            return None
        for release in releases:
            if not re.fullmatch(r'1\.(?:0|[1-9]\d*)', release.minor):
                return None
            date.fromisoformat(release.end_of_life)
        if len({s.url for s in sources}) != len(sources):
            return None
        for source in sources:
            if source.url not in URLS or not re.fullmatch(r'[0-9a-f]{64}', source.sha256):
                return None
            if source.digest_scope not in ('response-bytes', 'bundled-release-records'):
                return None
            observed = datetime.fromisoformat(source.observed_at)
            if observed.tzinfo is None or (observed - datetime.now(timezone.utc)).total_seconds() > 300:
                return None
        if not {SCHEDULE, HISTORY}.issubset({s.url for s in sources}):
            return None
        changed = tuple(data.get('changed_policies', ()))
        if any(url not in (SKEW, KUBEADM) for url in changed):
            return None
        return Knowledge(tuple(sorted(releases, key=lambda r: int(r.minor.split('.')[1]), reverse=True)), sources, changed_policies=changed)
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None


def bundled() -> Knowledge:
    return read(SEED_PATH) or Knowledge(error='Bundled release knowledge is unavailable; enter versions explicitly.')


def save(path: Path, knowledge: Knowledge) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    name = ''
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent, delete=False) as f:
            name = f.name
            json.dump(dict(schema=1, releases=[asdict(r) for r in knowledge.releases],
                           sources=[asdict(s) for s in knowledge.sources],
                           changed_policies=knowledge.changed_policies), f, indent=2)
        Path(name).replace(path)
    finally:
        if name:
            Path(name).unlink(missing_ok=True)


def fresh(knowledge: Knowledge, now: datetime | None = None) -> bool:
    now = now or datetime.now(timezone.utc)
    return set(s.url for s in knowledge.sources) == set(URLS) and all(
        0 <= (now - datetime.fromisoformat(s.observed_at)).total_seconds() < TTL_SECONDS for s in knowledge.sources)


def refresh(path: Path, previous: Knowledge | None = None, *,
            getter: Callable[[str], bytes] = fetch, force: bool = False) -> Knowledge:
    previous = previous or read(path) or bundled()
    if not force and not previous.error and fresh(previous):
        return previous
    bodies: dict[str, bytes] = {}
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        jobs = {url: pool.submit(getter, url) for url in URLS}
        for url, job in jobs.items():
            try:
                body = job.result()
                if not body or len(body) > MAX_BYTES:
                    raise ValueError('Invalid response size')
                bodies[url] = body
            except Exception:
                errors.append(url.rsplit('/', 1)[-1] + ' unavailable')
    observed = datetime.now(timezone.utc).isoformat()
    sources = {s.url: s for s in previous.sources}
    changed = set(previous.changed_policies)
    releases = previous.releases
    if SCHEDULE in bodies and HISTORY in bodies:
        try:
            current = parse_releases(bodies[SCHEDULE], bodies[HISTORY])
            combined = {r.minor: r for r in releases}
            combined.update({r.minor: r for r in current})
            releases = tuple(sorted(combined.values(), key=lambda r: int(r.minor.split('.')[1]), reverse=True))
            for url in (SCHEDULE, HISTORY):
                sources[url] = Evidence(url, hashlib.sha256(bodies[url]).hexdigest(), observed)
        except Exception:
            errors.append('Release feed format changed; keeping previous release data')
    for url in (SKEW, KUBEADM):
        if url in bodies:
            try:
                text = bodies[url].decode('utf-8')
                if 'version skew' not in text.lower() or '<html' in text.lower():
                    raise ValueError('Not a policy document')
                digest = hashlib.sha256(bodies[url]).hexdigest()
                if url in sources and sources[url].sha256 != digest:
                    changed.add(url)
                sources[url] = Evidence(url, digest, observed)
            except ValueError:
                errors.append('Policy document format changed; keeping previous evidence')
    result = Knowledge(releases, tuple(sources.values()), '; '.join(errors), tuple(sorted(changed)))
    if result.releases and (result.releases != previous.releases or result.sources != previous.sources):
        try:
            save(path, result)
        except OSError:
            result = replace(result, error=(result.error + '; ' if result.error else '') + 'Could not save refreshed knowledge')
    return result


def notices(knowledge: Knowledge, values: tuple[str, ...], today: date | None = None) -> list[str]:
    from k8s_version import api_minor
    today = today or date.today()
    rows = {r.minor: r for r in knowledge.releases}
    messages = []
    for value in dict.fromkeys(values):
        minor = api_minor(value)
        if minor is None:
            continue
        line = f'1.{minor}'
        release = rows.get(line)
        if release is None:
            messages.append(f'{line} is absent from the available upstream release data. Check the value or refresh; it remains usable.')
        elif date.fromisoformat(release.end_of_life) <= today:
            messages.append(f'{line} reached upstream end of life on {release.end_of_life}. Vendor support may differ; it remains selectable.')
    baseline = {s.url: s.sha256 for s in bundled().sources}
    for source in knowledge.sources:
        if source.url in (SKEW, KUBEADM) and (source.url in knowledge.changed_policies or
                (source.url in baseline and source.sha256 != baseline[source.url])):
            messages.append('Upstream ' + ('kubeadm' if source.url == KUBEADM else 'version-skew') + ' documentation changed since this build. Bundled compatibility rules need review; they were not replaced automatically.')
    if knowledge.error:
        messages.append('Refresh incomplete: ' + knowledge.error + '. Retaining available knowledge; retry will be attempted.')
    if not fresh(knowledge):
        messages.append('Using cached or bundled release/policy observations; current upstream state is not confirmed.')
    return messages


def summary(knowledge: Knowledge) -> str:
    observed = min((s.observed_at for s in knowledge.sources if s.url in (SCHEDULE, HISTORY)), default='unknown')
    return f'Kubernetes upstream release data observed {observed[:19]}. ' + ('Refresh incomplete; keeping available data.' if knowledge.error else 'Known releases do not guarantee repository availability or vendor support.')
