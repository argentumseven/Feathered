"""Advisories over acquired packages. Never alter a catalogue or resolution."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Protocol, Sequence
import re
from k8s_version import parse

POLICY_SOURCE = 'https://kubernetes.io/releases/version-skew-policy/'
COMPONENTS = frozenset({'kubectl', 'kubelet', 'kube-proxy', 'kubeadm', 'kube-apiserver', 'kube-controller-manager', 'kube-scheduler', 'cloud-controller-manager'})

class Package(Protocol):
    @property
    def name(self) -> str: ...
    @property
    def version(self) -> str: ...

@dataclass(frozen=True)
class Finding:
    package: str
    version: str
    severity: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def component(name: str) -> str:
    value = name.removeprefix('kubernetes-')
    return name if name in COMPONENTS else value if value in COMPONENTS else ''


def managed_kind(name: str) -> str:
    if name.startswith('linux-headers') or re.search(r'-(?:devel|headers|dev|docs?|tools|debuginfo|debugsource|sources?)(?:-|$)', name):
        return ''
    if (component(name) and component(name) != 'kubectl') or name in {'kubernetes', 'kubernetes-node', 'kubernetes-master', 'kubernetes-server'}:
        return 'node/control-plane'
    if name in {'antrea', 'calico', 'cilium', 'kubernetes-cni', 'cni-plugins', 'containernetworking-plugins'}:
        return 'cluster add-on'
    if name.startswith(('kernel', 'linux-image')) or name in {'containerd', 'containerd.io', 'runc', 'crun', 'cri-o', 'cri-tools', 'docker', 'docker-ce', 'docker-ce-cli', 'moby-engine'}:
        return 'node image'
    return ''


def platform_findings(packages: Sequence[Package]) -> list[Finding]:
    return [Finding(p.name, p.version, 'advisory', 'managed-platform-component',
        f'{kind} component: check the managed platform release/image or add-on workflow. Direct installation may be unsupported and may be replaced during node rollout.')
        for p in packages if (kind := managed_kind(p.name))]


def evaluate(packages: Sequence[Package], minor: int, oldest: int | None = None, newest: int | None = None) -> list[Finding]:
    # With neither bound supplied the API server range is not observed, it is
    # assumed equal to the selected repository minor. Findings that only make
    # sense against a real control plane are suppressed in that case rather
    # than reported against the assumption.
    assumed_api = oldest is None and newest is None
    low = oldest if oldest is not None else newest if newest is not None else minor
    high = newest if newest is not None else low
    result: list[Finding] = []
    def add(p: Package, code: str, message: str, severity: str = 'advisory') -> None:
        result.append(Finding(p.name, p.version, severity, code, message))
    if high < low or high - low > 1:
        result.append(Finding('(cluster)', f'1.{low}..1.{high}', 'conflict', 'api-server-set',
            'API server oldest/newest values are reversed or span more than one minor. Confirm the cluster values.'))
    seen: dict[str, int] = {}
    for p in packages:
        name = component(p.name)
        if not name:
            continue
        try:
            v = parse(p.version, require_patch=True, allow_prerelease=True)
        except ValueError as exc:
            add(p, 'unparsed-version', str(exc), 'info'); continue
        seen[name] = v.minor
        if v.prerelease:
            add(p, 'prerelease', 'Pre-release component; stable version-skew rules alone do not establish compatibility.')
        if name == 'kubeadm':
            if v.minor != minor:
                add(p, 'kubeadm-minor', f'kubeadm minor 1.{v.minor} differs from the selected repository minor 1.{minor}; review the intended lifecycle operation.', 'conflict')
            # kubeadm is not covered by the version-skew policy, so it is
            # evaluated separately. The previous `continue` here meant kubeadm
            # was only ever compared against the repository it came from, which
            # is near-tautological: kubeadm is pulled *from* that repository, so
            # the check above almost never fires. The case an operator needs
            # flagged -- kubeadm newer than the control plane it will drive, or
            # too old to upgrade it -- produced no finding at all.
            if not assumed_api:
                if v.minor > high + 1:
                    add(p, 'kubeadm-control-plane',
                        f'kubeadm 1.{v.minor} is more than one minor newer than the newest API server 1.{high}. '
                        f'Confirm the intended operation and the kubeadm version last used to manage the node.')
                elif v.minor < low:
                    add(p, 'kubeadm-control-plane',
                        f'kubeadm 1.{v.minor} is older than the oldest API server 1.{low}; '
                        f'Check the intended operation and the kubeadm version last used to manage the node.')
                elif v.minor == high + 1:
                    add(p, 'kubeadm-upgrade-intent',
                        f'kubeadm 1.{v.minor} is one minor newer than the newest API server 1.{high}, '
                        f'This may be an upgrade; join and upgrade have different requirements. Confirm the operation and prior kubeadm version.')
            continue
        if name == 'kubectl':
            lower, upper = high - 1, low + 1
        elif name == 'kube-apiserver':
            lower, upper = high - 1, low + 1
        else:
            window = (3 if v.minor >= 25 else 2) if name in {'kubelet', 'kube-proxy'} else 1
            # The intersection must satisfy *every* API server, not just oldest.
            lower, upper = high - window, low
        if not lower <= v.minor <= upper:
            add(p, 'component-skew', f'{name} minor 1.{v.minor} is outside 1.{lower}..1.{upper} for API servers 1.{low}..1.{high}.')
    if 'kubelet' in seen and 'kube-proxy' in seen:
        window = 3 if seen['kube-proxy'] >= 25 else 2
        if abs(seen['kubelet'] - seen['kube-proxy']) > window:
            result.append(Finding('kubelet/kube-proxy', '', 'advisory', 'node-pair-skew', f'Node component minors differ by more than {window}.'))
    return result
