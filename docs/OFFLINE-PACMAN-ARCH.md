# Build an offline pacman repository for Arch Linux or Artix Linux

Feathered can collect packages for Arch-family targets, transfer the required content across an air gap, and publish a native pacman repository for the disconnected system.

Built-in profiles currently cover Arch Linux and Artix Linux.

## Typical workflow

1. Choose the Arch Linux or Artix Linux target profile and architecture.
2. Select a workload, exact packages, or a complete repository mirror.
3. Enable the repositories allowed to participate in dependency planning.
4. Optionally load a target inventory.
5. Build the Feathered bundle.
6. Transfer the generated pacman repository into the disconnected environment.
7. Use the generated repository configuration and native pacman transaction on the target.

Saved build specifications can be executed headlessly:

```bash
python feathered_cli.py build --spec build.json --out ./bundles
```

## Full-upgrade semantics

Arch-family package management is a rolling-release system. Feathered therefore treats direct Arch-family installation with full-upgrade transaction semantics rather than presenting partial upgrade behavior as safe.

Installed inventory is optional. Without it, Feathered transfers a complete repository-derived dependency closure and leaves final transaction evaluation to pacman.

The native target package manager remains authoritative.

## Repository mirrors

Use **Entire repository (mirror)** when the goal is to move a complete selected repository rather than construct a package dependency closure.

Feathered can preserve repository boundaries or explicitly construct a unified publication. Artifact conflicts are not silently discarded when available metadata cannot establish that two matching package identities contain the same bytes.

## Differential bundles

Differential builds compare a new package set with a previous Feathered baseline. Content digests are preferred to package identity alone when deciding whether an artifact can be omitted from the transfer.

## Related documentation

- [Main README](../README.md)
- [CLI](../CLI.md)
- [Validation](../VALIDATION.md)
- [Security](../SECURITY.md)
