"""Build-output naming and publication-path policy.

Folder naming derives from the frozen request and its captured naming instant,
so confirmation and publication compute the same destination deterministically.

Imports no Tk, enforced by tests/test_build_request_module.py.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from acquisition_model import MirrorLayout
from feathered_app.build_request import BuildRequestMixin

FOLDER_SCHEMES = [
    "System and contents",
    "Contents only",
    "System only",
    "Custom label",
]


def folder_component(value: str, fallback: str = "repository") -> str:
    """Sanitize one human label for use inside an output folder name.

    A module-level function rather than a staticmethod on the wizard mixin, so
    the core can call it without reaching into a Tk module. OutputMixin keeps a
    staticmethod delegating here, because existing callers and tests reference
    it by that name.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-")
    return cleaned or fallback


def _layout(host) -> MirrorLayout:
    """Mirror layout, defaulting to the conservative one for partial hosts.

    Folder-naming tests drive these helpers with stubs that predate the layout
    control. Absent state must never be read as a request to merge
    repositories, so anything short of an explicit unified selection is the
    separate layout.
    """
    resolve = getattr(host, "_mirror_layout", None)
    return resolve() if callable(resolve) else MirrorLayout.SEPARATE


def _naming_moment(host):
    """The instant folder names are derived from.

    While a build is running this is the moment frozen when the request was
    captured, so the name computed at confirmation and the name computed at
    write time are identical by construction rather than by a lock that has to
    notice they diverged. Outside a build it is simply now, because the preview
    should track the clock.
    """
    frozen = host.__dict__.get("_build_naming_time")
    return frozen if frozen is not None else datetime.now()


def _frozen(host, accessor: str, variable: str) -> str:
    """Prefer the frozen build request, falling back to the live control.

    Folder-naming tests drive these helpers with stubs that predate the
    snapshot accessors, and those stubs supply only the Tk variables. The
    fallback keeps them working; the accessor is what makes the worker thread
    safe.
    """
    read = getattr(host, accessor, None)
    if callable(read):
        return read()
    var = host.__dict__.get(variable)
    return var.get().strip() if var is not None else ""


class BuildOutputMixin:
    """Output directory resolution and folder naming. No widget access."""

    def _folder_name(self, mirror_repo=None, naming_time=None) -> str:
        """Build one bundle folder name from the chosen naming scheme.

        In repository-mirror mode ``mirror_repo`` identifies one publication
        fork.  Every selected repository gets a unique sibling directory; the
        chosen date/date+time/custom label is a shared naming axis applied to
        all forks rather than a reason to merge their payloads.
        """
        release = _frozen(self, "_selected_release", "release_var")
        arch = BuildRequestMixin._selected_arch(self)
        target = f"{self._profile().key}-{release}-{arch}"
        # A unified mirror is a single publication, so it never carries a
        # per-repository folder component even when several are selected.
        unified = self._mirror_mode() and _layout(self) is MirrorLayout.UNIFIED
        mirror_fork = self._mirror_mode() and mirror_repo is not None and not unified
        repo_component = (folder_component(getattr(mirror_repo, "name", ""))
                          if mirror_fork else "")
        if self._mirror_mode():
            workload = ("mirror-unified" if unified else
                        f"mirror-{repo_component}" if mirror_fork else "mirror")
        elif self._single_mode():
            chosen = self.selected_packages
            workload = (chosen[0].name if len(chosen) == 1 else f"{len(chosen)}-packages") \
                if chosen else "packages"
        else:
            workload = self._workload().key
        scheme = BuildRequestMixin._selected_output_option(self, "folder_scheme", "folder_scheme_var")
        custom = BuildRequestMixin._selected_output_option(self, "folder_label", "folder_label_var").strip()
        if scheme == FOLDER_SCHEMES[3]:
            if mirror_fork:
                # Custom text is shared across all mirror forks, while the repo
                # suffix guarantees that eight selected repositories cannot
                # collapse back into one destination.
                stem = f"{custom}-{repo_component}" if custom else repo_component
            else:
                stem = custom
        elif scheme == FOLDER_SCHEMES[1]:
            stem = workload
        elif scheme == FOLDER_SCHEMES[2]:
            # "System only" is inherently non-unique for multi-repo mirroring;
            # append the repository identity only in that workflow.
            stem = f"{target}-mirror-{repo_component}" if mirror_fork else (
                f"{target}-mirror-unified" if unified else target)
        else:
            stem = f"{target}-{workload}"
        if scheme != FOLDER_SCHEMES[3]:
            stem = f"{stem}-offline"
        moment = naming_time or _naming_moment(self)
        stamp = BuildRequestMixin._selected_output_option(self, "folder_stamp", "folder_stamp_var")
        if stamp == "time":
            prefix = moment.strftime("%Y-%m-%d_%H%M%S")
        elif stamp == "date":
            prefix = moment.strftime("%Y-%m-%d")
        else:
            prefix = ""
        if prefix and stem:
            name = f"{prefix}_{stem}"
        elif prefix:
            name = prefix
        else:
            name = stem
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")
        if scheme == FOLDER_SCHEMES[3] and not cleaned:
            return ""
        return cleaned or "feathered-bundle"

    def _resolved_output_path(self, folder_name: str | None = None) -> Path:
        """Return the final bundle directory that a build will publish.

        ``out_var`` is only the parent
        directory selected on Transfer.  The real output is that directory plus
        Feathered's generated folder name; Review must display the latter.  A
        build passes its already-generated folder name so a date+time prefix
        cannot roll over between two calls.
        """
        base = Path(_frozen(self, "_selected_output_base", "out_var") or str(Path.cwd())).expanduser()
        return base / (folder_name or self._folder_name())

    def _mirror_output_folder_names(self, naming_time=None):
        """Return ``[(repo, folder_name), ...]`` for every selected mirror fork.

        Empty in the unified layout: that workflow produces a single directory
        and locks its name through the ordinary single-output path instead.
        """
        if self._mirror_mode() and _layout(self) is MirrorLayout.UNIFIED:
            return []
        repos_fn = getattr(self, "_selected_mirror_repositories", None)
        repos = list(repos_fn()) if callable(repos_fn) else [
            r for r in getattr(self, "repo_rows", [])
            if str(getattr(r, "url", "") or "").strip()
            and getattr(self, "_mirror_repo_selected", lambda _r: False)(r)]
        moment = naming_time or _naming_moment(self)
        rows = [(repo, BuildOutputMixin._folder_name(self, mirror_repo=repo, naming_time=moment))
                for repo in repos]
        counts = {}
        for _repo, name in rows:
            counts[name] = counts.get(name, 0) + 1
        if any(count > 1 for count in counts.values()):
            unique = []
            for repo, name in rows:
                if counts[name] > 1:
                    fingerprint = str(getattr(repo, "source_identity", ""))[-8:] or "source"
                    name = f"{name}-{fingerprint}"
                unique.append((repo, name))
            rows = unique
        return rows


    def _summarize_existing_output_folder(self, dest: Path) -> str:
        """Human summary of an already-populated publish folder."""
        try:
            entries = sorted(dest.iterdir(), key=lambda p: p.name.lower())
        except Exception:
            return f'"{dest.name}" already exists.'
        names = [p.name for p in entries]
        markers = []
        if any((dest / name).is_dir() for name in ("debs", "rpms", "packages")):
            markers.append("package payloads")
        if (any((dest / name).exists() for name in ("repodata", "dists", "metadata", "USE-AS-REPOSITORY.txt"))
                or (dest / "packages" / "feathered.db").exists()
                or (dest / "packages" / "feathered.db.tar.gz").exists()):
            markers.append("repository metadata")
        if (dest / "metadata" / "manifest.json").exists() or (dest / "manifest.json").exists():
            markers.append("bundle manifest")
        preview = ", ".join(names[:4])
        if len(names) > 4:
            preview += ", …"
        detail = f' It currently contains {len(entries)} item(s): {preview}.' if names else ""
        if markers:
            detail += " Detected: " + ", ".join(markers) + "."
        return f'"{dest.name}" already exists and is not empty.' + detail


    def _folder_has_repository_metadata(self, dest: Path) -> bool:
        """Return whether the output already carries generated local repo data."""
        dest = Path(dest)
        if (dest / "repodata" / "repomd.xml").is_file():
            return True
        if (dest / "dists" / "feathered" / "Release").is_file():
            return True
        package_dir = dest / "packages"
        if (package_dir / "feathered.db").is_file() or (package_dir / "feathered.db.tar.gz").is_file():
            return True
        return (dest / "USE-AS-REPOSITORY.txt").is_file()


    def _suggest_sibling_output_folder_name(self, base_name: str) -> str:
        """Return a new sibling folder name beside an occupied destination."""
        stamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        seed = re.sub(r"[^A-Za-z0-9._-]+", "-", f"{base_name}-refresh-{stamp}").strip("-") or "feathered-bundle-refresh"
        base = Path(_frozen(self, "_selected_output_base", "out_var") or str(Path.cwd())).expanduser()
        candidate = seed
        counter = 2
        while (base / candidate).exists():
            candidate = f"{seed}-{counter}"
            counter += 1
        return candidate



def confirm_publication(self, folder_name: str, options=None, *, choose, open_existing=None) -> str | None:
    """Compatibility adapter for callers supplying an App or source host."""
    from feathered_app.build_publication import PublicationContext, confirm_publication as confirm

    context = PublicationContext(
        resolve_path=self._resolved_output_path,
        is_mirror=lambda: getattr(self, "_mirror_mode", lambda: False)(),
        summarize=lambda dest: self._summarize_existing_output_folder(dest),
        suggest_sibling=lambda name: self._suggest_sibling_output_folder_name(name),
        has_repository_metadata=lambda dest: self._folder_has_repository_metadata(dest),
        log=lambda message: self._log(message),
    )
    return confirm(context, folder_name, options, choose=choose, open_existing=open_existing)
