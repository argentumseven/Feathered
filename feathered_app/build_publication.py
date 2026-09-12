"""Typed publication confirmation shared by the GUI and headless adapter."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from feathered_app.build_host_contracts import PublicationOptions, PublicationPolicy


@dataclass(frozen=True)
class PublicationContext:
    """Only the host capabilities publication confirmation can reach."""

    resolve_path: Callable[[str], Path]
    is_mirror: Callable[[], bool]
    summarize: Callable[[Path], str]
    suggest_sibling: Callable[[str], str]
    has_repository_metadata: Callable[[Path], bool]
    log: Callable[[str], None]


def confirm_publication(context: PublicationContext, folder_name: str,
                        options: PublicationOptions | None = None, *,
                        choose: PublicationPolicy,
                        open_existing: Callable[[Path], None] | None = None) -> str | None:
    """Negotiate an additive build into an already-populated folder.

    Existing destination-only content is never deleted. The default action
    adds/overwrites files in place after staging succeeds. If repository
    generation is enabled and existing local-repository metadata is found,
    a second explicit choice controls whether it is regenerated over the
    complete old+new package population.
    """
    dest = context.resolve_path(folder_name)
    if dest.exists() and not dest.is_dir():
        raise RuntimeError(
            f"The output destination '{dest}' already exists as a file. Choose a different output folder or label.")
    if not dest.is_dir():
        if options is not None:
            options.additive_publish = False
        return folder_name
    try:
        populated = any(dest.iterdir())
    except Exception:
        populated = True
    if not populated:
        if options is not None:
            options.additive_publish = False
        return folder_name

    if context.is_mirror():
        # A repository mirror must describe one source snapshot. Additive
        # publication would retain packages that disappeared upstream and
        # therefore turn the mirror into a historical union. Preserve the
        # existing folder and publish this run into a fresh sibling instead.
        message = (
            context.summarize(dest)
            + "\n\nRepository mirror outputs are non-additive. Reusing this populated folder "
              "would retain stale package artifacts and metadata from an older snapshot."
            + "\n\nUse a new sibling folder, or open the existing folder if you want to remove it manually first."
        )
        choice = choose(
            "Feathered",
            message,
            choices=(
                ("sibling", "Use a new sibling mirror folder (recommended)"),
                ("open", "Open existing folder so I can remove it manually"),
                ("cancel", "Cancel build"),
            ),
            default="sibling",
            kind="warning",
        )
        if choice == "open":
            try:
                open_existing(dest) if open_existing is not None else None
            except Exception as exc:
                context.log( f"Could not open the output folder.\n\n{exc}")
            return None
        if choice != "sibling":
            return None
        if options is not None:
            options.additive_publish = False
            options.emit_repository = True
        return context.suggest_sibling(dest.name)

    message = (
        context.summarize(dest)
        + "\n\nDefault: add this build to the existing folder. Feathered will keep unrelated files that are already there and build the complete successor in staging first. Final publication swaps the completed snapshot into place with rollback instead of modifying the published folder file by file."
        + "\n\nYou can also open the folder now if you want to remove anything manually before building."
    )
    choice = choose(
        "Feathered",
        message,
        choices=(
            ("add", "Add packages to this folder (recommended)"),
            ("sibling", "Use a new sibling folder instead"),
            ("open", "Open folder so I can delete files manually"),
            ("cancel", "Cancel build"),
        ),
        default="add",
        kind="warning",
    )
    if choice == "open":
        try:
            open_existing(dest) if open_existing is not None else None
        except Exception as exc:
            context.log( f"Could not open the output folder.\n\n{exc}")
        return None
    if choice == "sibling":
        if options is not None:
            options.additive_publish = False
        return context.suggest_sibling(dest.name)
    if choice not in {"add", "replace"}:  # "replace" accepted only for older test/API callers.
        return None

    if options is not None:
        options.additive_publish = True
        if bool(getattr(options, "emit_repository", False)) and context.has_repository_metadata(dest):
            repo_choice = choose(
                "Feathered",
                "Repository metadata already exists in this folder, and repository-data generation is enabled for this build.\n\nRegenerating it will overwrite the canonical repository index files so they describe all package payloads in the folder, including this addendum. Feathered will not delete older metadata files.\n\nChoose how to proceed.",
                choices=(
                    ("regenerate", "Regenerate repository metadata for all packages (recommended)"),
                    ("keep", "Keep existing repository metadata unchanged"),
                    ("open", "Open folder so I can inspect/delete files manually"),
                    ("cancel", "Cancel build"),
                ),
                default="regenerate",
                kind="warning",
            )
            if repo_choice == "open":
                try:
                    open_existing(dest) if open_existing is not None else None
                except Exception as exc:
                    context.log( f"Could not open the output folder.\n\n{exc}")
                return None
            if repo_choice == "cancel":
                return None
            if repo_choice == "keep":
                options.emit_repository = False
    return folder_name

