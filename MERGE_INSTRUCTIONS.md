# Feathered discoverability merge package

This package contains a conservative discoverability update for Feathered.

## Contents

- `README.patch` — replaces only the README title/introduction and inserts a search-oriented use-case section. The remainder of the existing README is left untouched.
- `docs/README.md` — guide index.
- `docs/OFFLINE-RPM-DNF-YUM.md` — RPM-family offline acquisition guide.
- `docs/OFFLINE-APT-DEBIAN-UBUNTU.md` — Debian-family offline acquisition guide.
- `docs/OFFLINE-PACMAN-ARCH.md` — Arch-family offline acquisition guide.
- `docs/AIRGAP-WINDOWS-WORKSTATION.md` — connected-Windows-to-disconnected-Linux workflow.
- `GITHUB_METADATA.md` — repository description, topics, release-title, and social-preview recommendations that require GitHub settings rather than a normal source merge.

## Apply

From the Feathered repository root:

```bash
git apply README.patch
cp -R path/to/this-package/docs ./docs
cp path/to/this-package/GITHUB_METADATA.md ./GITHUB_METADATA.md
```

If `docs/` already contains files, copy these files individually instead of replacing the directory.

Then review:

```bash
git diff -- README.md docs GITHUB_METADATA.md
```

## Scope

The update deliberately does not:

- alter Feathered's resolver/security semantics;
- invent new CLI flags;
- claim support not already described by the project;
- remove the detailed existing README;
- create thin keyword-only pages.

The new documentation reorganizes existing functionality around common search and operator intents.
