"""Repository-driven Kubernetes workloads, inventory baselines and recorded advice."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json
import re
from k8s_version import api_minor, parse
from k8s_policy import POLICY_SOURCE, Finding, evaluate, platform_findings
from k8s_knowledge import Knowledge

KUBERNETES_KEYS = frozenset({'kubernetes-node', 'kubernetes-client'})
VKS_KEY = 'vks-node-additions'
LABELS = {'kubernetes-node': 'Kubernetes node (kubeadm, self-managed)',
          'kubernetes-client': 'Kubernetes client tools (kubectl)', VKS_KEY: 'VKS node OS package additions'}
INVENTORY_MESSAGE = ('Load a captured node inventory for VKS OS additions. Photon updates and Ubuntu updates/security are rolling channels, while the node image is pinned at build time. The inventory is needed to avoid unrelated installed-library upgrades.')
LIMITS = 'Does not establish cluster upgrade readiness, container image availability, CNI/CSI compatibility, vendor support or Image Baker schema compatibility.'

@dataclass(frozen=True)
class WorkloadContext:
    workload: str = ''
    minor: str = ''
    oldest: str = ''
    newest: str = ''
    pin_baseline: bool = True
    acknowledged: bool = False
    platform_note: str = ''
    image_name: str = ''
    distribution: str = ''
    release: str = ''
    knowledge: Knowledge | None = None

    @property
    def active(self) -> bool:
        return self.workload in KUBERNETES_KEYS or self.workload == VKS_KEY

    def validate(self) -> None:
        for flag in (self.pin_baseline, self.acknowledged):
            if type(flag) is not bool:
                raise ValueError('Workload acknowledgement and baseline settings must be booleans.')
        for text in (self.minor, self.oldest, self.newest, self.platform_note, self.image_name):
            if not isinstance(text, str):
                raise ValueError('Workload version and note fields must be text.')
        if self.workload in KUBERNETES_KEYS:
            if not self.minor.strip():
                raise ValueError('Choose a Kubernetes minor on Content; that choice selects the repository. Refresh versions, or enter a minor if discovery is unavailable.')
            parse(self.minor)
            api_minor(self.oldest); api_minor(self.newest)
        if self.workload == VKS_KEY:
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,61}[a-z0-9])?', self.image_name):
                raise ValueError('Enter an Image Baker draft name on Content (lowercase letters, digits, dots or hyphens; up to 63 characters).')


def repository_template(family: str, minor: str):
    from profiles import RepoTemplate
    line = parse(minor).line
    deb = family == 'deb'
    if family not in {'deb', 'rpm'}:
        raise ValueError('Community Kubernetes package repositories support RPM and DEB targets.')
    return RepoTemplate(name=f'Kubernetes {line} (community)',
        url=f'https://pkgs.k8s.io/core:/stable:/v{line}/{"deb" if deb else "rpm"}/',
        role='kubernetes', priority=10, repo_format='apt' if deb else 'rpm',
        suite='/' if deb else '', components='', flat_repo=deb,
        note=f'Community repository for Kubernetes minor {line}; OS dependencies retain distribution sources. '
             f'The colons in the path are Open Build Service project namespacing '
             f'(isv:kubernetes:core:stable:v{line}), not a malformed URL. pkgs.k8s.io replaced the '
             f'Google-hosted apt.kubernetes.io/yum.kubernetes.io repositories and carries v1.24 and newer.')


def synchronize_repository(rows, family: str, minor: str, factory):
    """Rewrite only generated rows; explicit custom sources stay operator-owned."""
    template = repository_template(family, minor)
    existing = [r for r in rows if r.role == 'kubernetes']
    generated = [r for r in existing if getattr(r, 'workload_profile_managed', False)]
    if existing and not generated:
        return False
    if generated:
        first = generated[0]
        changed = first.url != template.url
        for key in ('name', 'url', 'repo_format', 'suite', 'components', 'flat_repo'):
            setattr(first, key, getattr(template, key))
        # Never retain an old generated minor alongside the new one.
        rows[:] = [r for r in rows if r not in generated[1:]]
        return changed
    repo = factory(template, 'workload')
    repo.workload_profile_managed = True
    rows.append(repo)
    return True


def rolling_source(repo) -> bool:
    return repo.role == 'photon_updates' or 'photon updates' in repo.name.lower() or '/photon_updates_' in repo.url or ('/photon/' in repo.url and '/updates/' in repo.url) or (
        repo.repo_format == 'apt' and repo.suite.endswith(('-updates', '-security')))


def enforce_baseline(result, inventory) -> None:
    """Do not silently replace installed packages when the baseline is pinned."""
    installed = {(p.name, p.arch): p for p in inventory.retained_packages}
    changed = [p for p in result.selected if (p.name, p.arch) in installed
               and p.evr_text != installed[p.name, p.arch].evr_text]
    if changed:
        raise ValueError('Pinned inventory baseline would change installed packages: ' + ', '.join(p.name + ' ' + p.evr_text for p in changed) + '. Select a compatible package/source snapshot, or deliberately uncheck Pin to inventory baseline.')


def report(context: WorkloadContext, packages) -> dict:
    from dataclasses import asdict
    import k8s_knowledge
    findings = []
    assumed = not (context.oldest.strip() or context.newest.strip())
    if context.workload in KUBERNETES_KEYS:
        findings = evaluate(packages, parse(context.minor).minor, api_minor(context.oldest), api_minor(context.newest))
    knowledge = context.knowledge or k8s_knowledge.bundled()
    if context.workload in KUBERNETES_KEYS:
        findings.extend(Finding('(upstream knowledge)', '', 'advisory', 'release-knowledge', message)
                        for message in k8s_knowledge.notices(knowledge, (context.minor, context.oldest, context.newest)))
    platform = platform_findings(packages) if context.workload == VKS_KEY else []
    from k8s_policy import component
    from core import redact_url
    if context.workload in KUBERNETES_KEYS:
        for package in packages:
            if not component(package.name):
                continue
            try:
                actual = parse(package.version, allow_prerelease=True).line
            except ValueError:
                continue
            if actual != parse(context.minor).line:
                findings.append(Finding(package.name, package.version, 'advisory', 'selected-minor-source',
                    f'This source supplies component minor {actual}, different from the selected repository minor {parse(context.minor).line}. Review the explicit source override; this package remains selected.'))
    sources = [{'package': p.name, 'version': p.evr_text, 'repository': redact_url(p.repo.normalized_url)}
               for p in packages if component(p.name)]
    # Observations are emitted even for overrides and additive/mirror output.
    # No blanket claim that all packages came from the selected community repo.
    # apiserver_assumed is meaningless for VKS OS additions, which involve no
    # API server at all. Report it as None there, the way pin_to_inventory_
    # baseline is already scoped, rather than emitting a stray true.
    return {'workload': context.workload, 'selected_minor': parse(context.minor).line if context.workload in KUBERNETES_KEYS else '',
        'apiserver_assumed': assumed if context.workload in KUBERNETES_KEYS else None,
        'apiserver_oldest': context.oldest, 'apiserver_newest': context.newest,
        'upstream_knowledge': asdict(knowledge) if context.workload in KUBERNETES_KEYS else None,
        'policy_source': POLICY_SOURCE, 'findings': [f.as_dict() for f in findings],
        'platform_advisories': [f.as_dict() for f in platform], 'component_sources': sources,
        'advisories_acknowledged': context.acknowledged, 'platform_note': context.platform_note,
        'pin_to_inventory_baseline': context.pin_baseline if context.workload == VKS_KEY else None,
        'proves': 'Records the acquired component versions and source URLs and the advisory evaluation for this acquisition. Assumed API versions are not observed cluster state; retained additive files are outside this evaluation.',
        'does_not_prove': LIMITS}


def check_acknowledgement(data: dict) -> None:
    conflicts = [f for f in data['findings'] if f['severity'] == 'conflict']
    if conflicts and not data['advisories_acknowledged']:
        raise ValueError('Review and acknowledge these findings before building:\n' + '\n'.join(f"{f['package']} {f['version']}: {f['message']}" for f in conflicts))


def write_image_draft(destination: Path, context: WorkloadContext, result) -> None:
    # JSON scalar quoting is YAML-compatible and preserves arbitrary operator notes.
    repositories = sorted({str(p.relative_to(destination)) for p in destination.rglob('repodata/repomd.xml')})
    repositories += sorted({str(p.relative_to(destination)) for p in destination.rglob('Release')})
    names = list(dict.fromkeys(p.name for p in result.roots))
    lines = ['# UNVALIDATED Image Baker draft: reconcile with your VKS/Image Baker schema version.',
        '# Kubernetes settings must come from the intended VKr details; no version is inferred.',
        'apiVersion: imagebaker.vmware.com/v1alpha1', 'kind: Image', 'metadata:',
        '  name: ' + json.dumps(context.image_name), 'spec:', '  osSpec:',
        '    distribution: ' + json.dumps(context.distribution), '    release: ' + json.dumps(context.release),
        '  kubernetesSpec: {} # Fill from your VKr details using the supported schema.',
        '  repositorySpec:', '    # Local emitted metadata paths; translate to the schema and accessible URLs used by your builder.',
        '    localMetadata: ' + json.dumps(repositories), '  packages: ' + json.dumps(names)]
    (destination / 'imagebaker-image.yaml').write_text('\n'.join(lines) + '\n', encoding='utf-8')
