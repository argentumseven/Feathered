"""GUI-independent projection of the current repository source requirements.

SourcesMixin used to combine these decisions with Tk tree refreshes and indirect
calls into several other mixins. Callers now supply a complete, explicit source
snapshot; this module neither reads App state nor modifies repository objects.
"""
from __future__ import annotations

from typing import Callable, Collection, Mapping, Sequence

from credential_redaction import redact_url


# (tree key, operator-facing state, source name, location/description, tag)
SourceStatusRow = tuple[str, str, str, str, str]


class RepositoryStatusService:
    """Project configured sources onto the requirements visible in the wizard."""

    @staticmethod
    def rows(repositories: Sequence[object], *, mode: str,
             selected_mirror_ids: Collection[str] = (),
             exact_packages: Sequence[object] = (),
             required_roles: Sequence[str] = (),
             source_plan: Sequence[tuple[str, str, str]] = (),
             templates_by_role: Mapping[str, Sequence[object]] | None = None,
             tier_of: Callable[[object], str] | None = None,
             incompatibility: Callable[[object], str] | None = None,
             workload_target_issue: str = "",
             mirror_incompatibility: Callable[[object], str] | None = None) -> list[SourceStatusRow]:
        repos = tuple(repositories)
        result: list[SourceStatusRow] = []

        # The caller supplies the same target/init policy used by acquisition.
        # Mirror mode deliberately ignores it: mirroring does not install the
        # selected packages on the currently selected target.
        issue = incompatibility or (lambda _repo: "")

        if mode == "mirror":
            selected = frozenset(selected_mirror_ids)
            for index, repo in enumerate(repos):
                identity = getattr(repo, "source_identity", repo.name)
                if str(repo.url or "").strip() and identity in selected:
                    # Display names are not identities: two mirrors may share a name.
                    mirror_issue = mirror_incompatibility(repo) if mirror_incompatibility else ""
                    result.append((f"mirror:{index}:{identity}",
                                   "Incompatible" if mirror_issue else "Ready", repo.name,
                                   mirror_issue or redact_url(repo.url),
                                   "incompatible" if mirror_issue else "ready"))
            return result

        if mode == "exact":
            for index, pkg in enumerate(exact_packages):
                source = pkg.repo
                identity = getattr(source, "source_identity", None)
                matching = [repo for repo in repos if
                    repo.enabled and str(repo.url or "").strip() and
                    (getattr(repo, "source_identity", None) == identity
                     if identity is not None else repo.name == source.name)
                ]
                enabled = any(not issue(repo) for repo in matching)
                excluded = next((issue(repo) for repo in matching if issue(repo)), "")
                # One row per root, even if two roots come from the same repo.
                result.append((f"exact:{index}:{identity or source.name}",
                               "Ready" if enabled else "Incompatible" if excluded else "Disabled",
                               source.name,
                               redact_url(source.url) if enabled or not excluded else excluded,
                               "ready" if enabled else "incompatible" if excluded else "disabled"))
            return result

        if mode != "workload":
            raise ValueError(f"Unsupported source-status mode: {mode!r}")

        if workload_target_issue:
            return [("target", "Incompatible", "Workload / target",
                     workload_target_issue, "incompatible")]

        templates = templates_by_role or {}
        # Source roles may be referenced by several roots, but the status tree
        # must contain each role once and have unique tree-item identifiers.
        for role in dict.fromkeys(required_roles):
            configured = [repo for repo in repos if repo.role == role]
            candidates = [repo for repo in configured if repo.enabled and str(repo.url or "").strip()]
            enabled = [repo for repo in candidates if not issue(repo)]
            excluded = [repo for repo in candidates if issue(repo)]
            proposed = templates.get(role, ())
            key = f"role:{role}"
            if enabled:
                best = min(enabled, key=lambda repo: (repo.priority, repo.name))
                result.append((key, "Ready", best.name, redact_url(best.url), "ready"))
            elif excluded:
                best = min(excluded, key=lambda repo: (repo.priority, repo.name))
                result.append((key, "Incompatible", best.name, issue(best), "incompatible"))
            elif configured:
                best = min(configured, key=lambda repo: (repo.priority, repo.name))
                result.append((key, "Disabled", best.name, redact_url(best.url) if best.url else "<not configured>",
                               "disabled"))
            elif proposed:
                best = min(proposed, key=lambda repo: (not repo.enabled, repo.priority, repo.name))
                eligible_templates = [repo for repo in proposed if not issue(repo)]
                if eligible_templates:
                    best = min(eligible_templates, key=lambda repo: (not repo.enabled, repo.priority, repo.name))
                    result.append((key, "Available to add", best.name,
                                   redact_url(best.url) if best.url else "<manual setup>", "available"))
                else:
                    result.append((key, "Incompatible", best.name, issue(best), "incompatible"))
            else:
                result.append((key, "Source needed", "No profile source defined",
                               "Configure manually", "missing"))

        if any(kind == "distribution" for _name, kind, _role in source_plan):
            if tier_of is None:
                raise ValueError("A repository-tier classifier is required for distribution roots")
            configured_base = [repo for repo in repos if tier_of(repo) == "base"
                               and repo.enabled and str(repo.url or "").strip()]
            enabled_base = [repo for repo in configured_base if not issue(repo)]
            if enabled_base:
                names = ", ".join(repo.name for repo in sorted(
                    enabled_base, key=lambda repo: (repo.priority, repo.name))[:4])
                more = len(enabled_base) - 4
                if more > 0:
                    names += f" + {more} more"
                result.append(("distribution", "Ready", names,
                               "All enabled distribution repositories are eligible", "ready"))
            elif configured_base:
                best = min(configured_base, key=lambda repo: (repo.priority, repo.name))
                result.append(("distribution", "Incompatible", best.name,
                               issue(best), "incompatible"))
            else:
                result.append(("distribution", "Source needed",
                               "No distribution repository enabled",
                               "Enable at least one base distribution source", "missing"))

        if any(kind == "enabled" for _name, kind, _role in source_plan):
            configured = [repo for repo in repos if repo.enabled and str(repo.url or "").strip()]
            enabled_count = sum(not issue(repo) for repo in configured)
            excluded = next((issue(repo) for repo in configured if issue(repo)), "")
            result.append(("enabled", "Ready" if enabled_count else "Incompatible" if excluded else "Source needed",
                           f"{enabled_count} enabled repository/repositories" if enabled_count else "None",
                           "Operator-defined roots may use any enabled repository" if enabled_count else
                           excluded or "Enable a compatible repository",
                           "ready" if enabled_count else "incompatible" if excluded else "missing"))
        return result
