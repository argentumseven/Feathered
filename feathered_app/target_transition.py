"""Target and workload selection state, independent of the desktop shell.

The GUI owns widgets and invokes refresh callbacks. This service owns the
state that must survive switching profiles/workloads and the deterministic
part of retargeting the transaction repository universe. Nothing here reads
Tk variables, application mixins, or process-wide singleton state.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, TypeVar

Repo = TypeVar("Repo")
WorkloadContext = tuple[str, str, str, str]


@dataclass(frozen=True)
class WorkloadControls:
    """Snapshot of the editable version controls for one workload context."""

    version: str
    versions: tuple[str, ...]
    kubernetes_minor: str


@dataclass
class TargetTransitionService:
    """Own target-specific selections, not the widgets displaying them."""

    remembered_releases: dict[str, str] = field(default_factory=dict)
    current_profile: str | None = None
    workload_versions: dict[WorkloadContext, WorkloadControls] = field(default_factory=dict)
    current_workload: WorkloadContext | None = None
    last_workload_key: str | None = None

    def select_profile(self, *, profile: str, known: Iterable[str], current: str,
                       default: Callable[[list[str]], str] | None = None) -> str:
        """Remember the outgoing release and select only from the new target.

        An empty release catalogue must clear the previous target's release;
        that prevents generating plausible-looking but incorrect repository URLs.
        """
        if self.current_profile:
            self.remembered_releases[self.current_profile] = current.strip()
        self.current_profile = profile
        available = list(known)
        remembered = self.remembered_releases.get(profile)
        if remembered in available:
            return remembered
        if current in available:
            return current
        if not available:
            return ""
        # A fresh target defaults to its newest *stable* release, not merely
        # the first entry (which may be a development/beta series).
        chosen = default(available) if default is not None else ""
        return chosen if chosen in available else available[0]

    def switch_workload(
        self,
        context: WorkloadContext,
        *,
        current: WorkloadControls,
        has_version_axis: bool,
    ) -> WorkloadControls | None:
        """Save outgoing version controls and return incoming controls, if new.

        ``None`` means the context has not changed and the UI must not reset
        the current controls. The caller captures controls on the UI thread.
        """
        if context == self.current_workload:
            return None
        if self.current_workload is not None:
            self.workload_versions[self.current_workload] = current
        self.current_workload = context
        restored = self.workload_versions.get(context)
        if not has_version_axis:
            # Versionless workloads are never allowed to inherit a version
            # selector from a different workload or an obsolete saved state.
            return WorkloadControls("Follows repositories", (),
                                    restored.kubernetes_minor if restored else current.kubernetes_minor)
        return restored if restored is not None else WorkloadControls(
            "Latest", ("Latest",), current.kubernetes_minor)

    @staticmethod
    def transaction_rows_for_target(
        rows: Iterable[Repo], *, has_release: bool,
        tier_of: Callable[[Repo], str],
    ) -> list[Repo]:
        """Keep operator sources, discard old base sources and stale managed ones.

        When the new release is known, managed workload sources remain long
        enough for the profile's templates to retarget them by role.
        """
        return [r for r in rows if tier_of(r) != "base"
                and (has_release or not getattr(r, "workload_profile_managed", False))]

    @staticmethod
    def retarget_managed_workload_rows(
        rows: Iterable[Repo], *, templates: Iterable[Repo],
        tier_of: Callable[[Repo], str],
    ) -> None:
        """Update only profile-managed workload entries, never manual entries.

        Match roles rather than display names. A missing role is disabled
        instead of leaving a stale repository URL active for the new target.
        """
        by_role: dict[str, list[Repo]] = {}
        for template in templates:
            by_role.setdefault(template.role, []).append(template)
        for repo in rows:
            if tier_of(repo) != "workload" or not getattr(repo, "workload_profile_managed", False):
                continue
            choices = by_role.get(repo.role, [])
            if not choices:
                repo.enabled = False
                continue
            template = min(choices, key=lambda r: (not r.enabled, r.priority, r.name))
            repo.name = template.name
            repo.url = template.url
            repo.priority = template.priority
            repo.target_release = template.target_release
            repo.repo_format = getattr(template, "repo_format", repo.repo_format)
            repo.suite = getattr(template, "suite", repo.suite)
            repo.components = getattr(template, "components", repo.components)
            repo.expected_release_version = getattr(template, "expected_release_version", "")
            repo.evidence_suggestions = list(getattr(template, "evidence_suggestions", []) or [])
