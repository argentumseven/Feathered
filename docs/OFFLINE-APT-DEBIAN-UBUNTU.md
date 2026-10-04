# Download DEB packages and dependencies for offline Debian, Ubuntu, or Devuan

Feathered can collect Debian-family packages and their dependency closure on a connected workstation, generate a native APT repository, and transfer that repository to a disconnected or air-gapped Linux system.

The result is intended to be consumed by APT on the target rather than installed as an unordered directory of `.deb` files.

## Supported APT-family targets

Built-in Feathered profiles include:

- Ubuntu;
- Debian;
- Devuan;
- custom APT repositories.

Target architecture choices depend on the selected profile.

## Typical offline APT workflow

1. Choose the target distribution, release, and architecture.
2. Choose **Workload**, **Choose packages**, or **Entire repository (mirror)**.
3. Enable the target-compatible repositories allowed to satisfy dependencies.
4. Optionally import a target inventory from the disconnected system.
5. Configure the desired provenance and keying policy.
6. Build the Feathered bundle.
7. Transfer the generated APT repository to the offline environment.
8. Install through APT using the generated repository configuration or import the repository into your normal disconnected repository infrastructure.

A saved build specification can also be executed without the GUI:

```bash
python feathered_cli.py build --spec build.json --out ./bundles
```

See [CLI.md](../CLI.md) for runtime credentials, trust material, output reuse, and exit-code behavior.

## Dependency semantics

Feathered performs connected-side package analysis so required content is available before the target system runs APT.

Planning accounts for Debian-family dependency relationships including providers, versions, alternatives, architecture rules, installed-state reconciliation, and retained-package conflicts. Fresh target inventories also preserve installed `Conflicts` and `Breaks` declarations so selected packages can be checked against packages that will remain installed.

Unsupported or ambiguous dependency expressions are surfaced rather than guessed.

The final transaction still belongs to APT. Generated direct-install workflows isolate the transferred Feathered repository from unrelated network repositories and invoke `apt-get` against the offline content.

## Signed repository metadata

Where source policy and trust material permit it, Feathered can verify signed APT Release/InRelease metadata and the package checksums authenticated by that metadata.

A configured keyring is not treated as proof by itself. Feathered records OpenPGP coverage from signatures that were actually verified.

Devuan's built-in sources may use upstream HTTP defaults. In that case, use a trusted Devuan archive keyring to authenticate signed metadata and package checksums. Signature verification authenticates repository content; it does not encrypt HTTP transport.

## Complete APT mirrors

Choose **Entire repository (mirror)** when the goal is to transfer the full repository rather than only the packages required by a workload or selected roots.

The default output preserves source boundaries. Unified publication is explicit, and artifact equivalence is not inferred merely from matching package name/version metadata when stronger content identity is unavailable.

## Release boundaries

A Feathered bundle is built for a specific distribution and release. The receiver compares the target's `/etc/os-release` information with the bundle target even when no inventory was captured.

Feathered does not perform Debian-family release upgrades. For an air-gapped release upgrade, mirror the new release repositories with Feathered and then run the distribution's documented upgrade procedure against those local repositories.

## Related documentation

- [Main README](../README.md)
- [CLI](../CLI.md)
- [Validation](../VALIDATION.md)
- [Security](../SECURITY.md)
