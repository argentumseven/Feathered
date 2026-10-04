# Download RPM packages and dependencies for offline RHEL, Rocky Linux, AlmaLinux, CentOS Stream, or Fedora

Feathered can collect RPM packages and their dependency closure on a connected workstation, publish the result as a native RPM/YUM/DNF repository, and transfer that repository into a disconnected or air-gapped Linux environment.

This workflow is intended for operators who would otherwise need to combine `dnf download`, `repoquery`, `reposync`, repository metadata generation, and manual transfer steps.

## Supported RPM-family targets

Built-in Feathered profiles include:

- Red Hat Enterprise Linux (RHEL);
- Rocky Linux;
- AlmaLinux;
- CentOS Stream;
- Fedora;
- VMware Photon OS;
- custom RPM repositories.

Target architecture choices depend on the selected profile.

## Typical offline RPM workflow

1. On the connected Feathered workstation, choose the target distribution, release, and architecture.
2. Select one of Feathered's acquisition modes:
   - **Workload** for a dependency-complete predefined or organization-defined package set;
   - **Choose packages** for selected package identities and versions;
   - **Entire repository (mirror)** when the full upstream repository must cross the air gap.
3. Enable the repositories that are allowed to satisfy transitive dependencies.
4. Optionally load a target inventory captured from the disconnected system so planning can account for installed packages and package-manager state.
5. Select the required provenance and keying policy.
6. Build the bundle.
7. Transfer the generated repository across the air gap.
8. Consume the repository with the target system's native DNF/YUM tooling or stage it into repository-management infrastructure such as Red Hat Satellite or Pulp.

For headless builds, a saved Feathered build specification can be executed with:

```bash
python feathered_cli.py build --spec build.json --out ./bundles
```

Runtime credentials and local trust material can be supplied separately through the runtime configuration described in [CLI.md](../CLI.md).

## Dependency handling

Feathered performs connected-side analysis so the package content required by the requested workload can be transported before DNF/YUM is available on the disconnected side.

RPM planning includes package providers, version relationships, architecture rules, installed-state reconciliation, conflicts, and module metadata where required. Feathered deliberately does not replace DNF's final transaction solver. The generated direct-install workflow runs the native package manager against the emitted offline repository.

If a modular RPM would require module metadata that cannot be safely established, Feathered refuses to publish it as an orphan modular package rather than silently constructing an incomplete repository.

## RHEL CDN repositories

RHEL CDN access requires operator-supplied entitlement material. Private entitlement keys are runtime inputs and are not intended to become part of the portable build specification or published bundle.

Selecting RHEL CDN BaseOS/AppStream establishes those repositories as dependency providers. Missing entitlement material blocks authenticated access rather than silently degrading a dependency-complete request into a package-only result.

## Full repository mirroring

Use **Entire repository (mirror)** when you need every published package record from the selected source rather than a dependency closure.

Feathered can preserve each upstream source as a separate output repository or create an explicitly unified publication. When two repositories contain the same package identity, Feathered does not assume the artifacts are equal merely because their NEVRA matches; available content-digest evidence is used to establish equality.

## Differential offline updates

A later Feathered build can be compared with a previous Feathered baseline. Strong content digests are preferred over package-name/version identity, so a package republished under the same NEVRA with different bytes is not incorrectly omitted.

The differential bundle records the baseline package identities expected on the receiving side, and receiver-side checks validate those prerequisites.

## Verification and trust

Depending on policy and source capabilities, Feathered can record:

- repository metadata digest coverage;
- RPM/vendor package signatures;
- package SHA-256 or stronger digest evidence;
- corroboration from a second endpoint;
- independent Enterprise Linux peer evidence;
- operator signing of the completed bundle.

These are recorded as separate evidence claims rather than collapsed into a single generic "verified" status.

## Related documentation

- [Main README](../README.md)
- [CLI](../CLI.md)
- [Validation](../VALIDATION.md)
- [Security](../SECURITY.md)
