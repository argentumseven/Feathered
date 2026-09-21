<img width="2172" height="724" alt="473458245872458" src="https://github.com/user-attachments/assets/b3b9d422-2540-471e-9814-e636100a0a4b" />

# Feathered 1.3.0

Feathered downloads Linux workloads, individual packages, and complete repositories for use offline. Choose what to collect, select the sources, and build a bundle. Archive keyrings, independent evidence, vendor signature requirements, and bundle signing are optional.

From a connected Windows workstation, Feathered can acquire, verify, curate, and mirror RPM, APT, and pacman content, then publish native repositories for transfer into a disconnected network. Those repositories can be consumed directly by native package managers or staged into downstream repository-management infrastructure such as Red Hat Satellite or Pulp.

Feathered is not a replacement for APT, DNF, or pacman. Its connected-side resolver determines the content that must cross the air gap. The native package manager remains authoritative for the final transaction on the target system.

## What Feathered does

Feathered supports three primary acquisition modes:

- **Workload** - select a built-in or organization-defined workload and construct the package set needed to support it.
- **Choose packages** - select exact package identities and versions from configured repositories.
- **Entire repository (mirror)** - mirror complete selected repositories without reducing them through dependency resolution.

A build can produce:

- native RPM/YUM/DNF repositories;
- native APT repositories;
- native pacman repositories;
- separate per-source repository mirrors or an explicitly unified publication;
- differential bundles against a previous Feathered baseline;
- provenance, manifests, checksums, and receiver-side verification material;
- an offline installer for direct target consumption when the selected workflow supports it.

Workload mode offers dependency-complete acquisition and an explicit **Workload packages only** alternative. Workload/vendor repositories constrain where requested roots come from; every other enabled target-compatible repository may satisfy transitive dependencies. If the operator disables every separate dependency provider, Feathered falls back to package-only acquisition instead of pretending the workload is install-complete. Package-only output is not represented as a complete offline transaction and does not receive the normal offline installer.

## Default workflow

Choose a distribution and release, then select a workload, exact packages, or a
repository mirror. Use the default **Verify what is available** policy to check
published package digests without requiring archive keyrings or a second mirror.
Target inventory is optional. Workload packages can also be collected without
dependencies through **Workload packages only**.

Stronger provenance is available on Provenance and Keying. **Skip upstream
provenance checks** remains an explicit option; it also bypasses configured
archive keyrings. Bundle hashes record transfer integrity separately from
upstream authenticity.

Devuan's built-in sources retain the upstream HTTP defaults. The Repositories
and Provenance and Keying pages warn when participating sources use HTTP.
Configure a trusted Devuan archive keyring to authenticate signed metadata and
its package checksums. Obtain the keyring through a trusted channel, such as an
existing trusted Devuan installation's `devuan-keyring` package. Keep upstream
checks enabled to use it. Signatures authenticate content but do not encrypt HTTP.
See [Devuan's package source instructions](https://www.devuan.org/os/packages).

## Typical deployment model

A common repository-staging workflow is:

```text
Internet-facing repositories
          |
          v
      Feathered
  acquire / verify
  curate / mirror
  publish native repo
          |
          | transfer boundary
          v
  air-gapped staging
          |
          +--> Red Hat Satellite custom repository
          +--> Pulp
          +--> internal YUM/DNF server
          +--> internal APT server
          +--> internal pacman repository
          +--> standalone Linux target
```

Feathered publishes standard package repositories. It does not generate a native Satellite Inter-Satellite Synchronization export; when used with Satellite, the normal use case is to expose or import the Feathered-produced repository as custom content inside the disconnected environment.

<img width="1491" height="1055" alt="2361236713136736711367" src="https://github.com/user-attachments/assets/42a42cf4-92ac-4578-95a6-e2c5bdd1b465" />

## Supported targets

Built-in distribution profiles cover:

| Family | Profiles |
| --- | --- |
| RPM | RHEL, Rocky Linux, AlmaLinux, CentOS Stream, Fedora, VMware Photon OS, custom RPM repositories |
| APT | Ubuntu, Debian, Devuan, custom APT repositories |
| pacman | Arch Linux, Artix Linux |

Architecture choices are profile-specific. Feathered also supports target inventory capture so repository planning can account for installed packages, package relationships, architecture, and relevant package-manager state.

RHEL CDN access uses operator-supplied entitlement material. Selecting RHEL CDN BaseOS/AppStream establishes them as dependency providers even before credentials are configured; missing entitlement blocks authenticated repository access rather than changing the workload to package-only mode. Private entitlement keys are runtime inputs and are not intended to become part of the portable build specification or published bundle.

## Repository semantics

### Curated repositories

Workload and exact-package builds construct a controlled publication from the repositories that participate in the selected source plan. Feathered computes a conservative transfer closure, acquires the selected artifacts, and emits native repository metadata.

The final install transaction is still evaluated by the target package manager. Generated direct-install workflows isolate the transferred repository from unrelated network repositories and invoke the native tool:

- APT targets use `apt-get` with the Feathered repository as the configured source.
- RPM targets use DNF/YUM with other repositories disabled.
- Arch-family targets use pacman with a generated repository configuration and full-upgrade transaction semantics.

### Repository mirrors

Mirror mode is not dependency resolution. It inventories every published package record from each selected repository.

The default **separate** layout preserves repository boundaries: one upstream source becomes one output repository.

The **unified** layout is a new merged publication. When repositories contain the same package identity, Feathered only treats the artifacts as equal when available metadata establishes equality. Digest disagreement is a conflict. Unknown equivalence is not silently promoted to equality. An operator-selected priority decision remains recorded as a priority choice rather than proof that the discarded artifacts were identical.

### Differential bundles

Differential builds compare package content against a previous Feathered baseline. Strong content digests are preferred over package-name/version identity, so a republished package with the same NEVRA/version but different bytes is not incorrectly omitted.

A differential bundle records the baseline package identities expected to exist on the receiving target. Receiver-side checks verify those prerequisites before installation.

## Dependency and target-state model

Feathered performs connected-side package analysis so that required content can be transported before the native target solver is available.

Fresh target inventories retain installed conflict declarations. Selected packages are checked against the packages that remain installed, including Debian Conflicts and Breaks. Older inventories without those declarations cannot establish the same coverage; collect again to include them. Inventory remains optional.

The resolver includes package-family-specific handling for providers, versions, alternatives, conflicts, architecture rules, installed-state reconciliation, retained-package relationships, and iterative transaction constraints. It is deliberately conservative where native semantics cannot be established safely.

Important boundaries:

- Native APT, DNF/YUM, and pacman transaction checks remain authoritative.
- RPM module metadata is retained when needed; modular RPMs without matching module metadata are refused rather than published as orphan modular content.
- RPM dependency planning follows module runtime requirements from repository defaults and captured enabled streams. It handles transitive requirements, cycles, stream exclusions, alternative dependency blocks, and contexts constrained by the captured platform and module state.
- Conflicting or ambiguous module choices exclude the affected candidates and produce a diagnostic when the request needs them. Unrelated nonmodular packages remain available. Feathered does not reproduce DNF's relaxed solver fallbacks or switch enabled streams automatically. The generated installer runs DNF against the emitted offline repository; it cannot fetch packages omitted by the builder.
- Package-only acquisition does not require module dependency resolution. It preserves available module metadata but makes no claim that the downloaded package is an installable transaction.
- Arch-family installs use full-upgrade semantics. Installed inventory is optional; when it is absent Feathered transfers a complete repository-derived dependency closure and leaves the final transaction to pacman.
- Unsupported or ambiguous dependency expressions are blocked or surfaced rather than guessed.

## Provenance and verification

Feathered records provenance on independent axes instead of reducing trust to one "verified" flag.

Depending on the source and policy, evidence can include:

- repository metadata digest coverage;
- signed APT Release/InRelease chains;
- RPM/vendor package signatures;
- package SHA-256 or stronger configured digest evidence;
- exact-byte corroboration from a second endpoint;
- authority relationships for corroborating sources;
- independently rebuilt Enterprise Linux peer evidence;
- operator signing of the completed bundle.

These claims are intentionally distinct. For example, a second mirror can show that another endpoint supplied identical bytes, but that does not by itself establish an independent publisher. An independently rebuilt peer can corroborate package/source lineage while intentionally producing different binary bytes.

Every recorded assurance mode has explicit **proves** and **does not prove** semantics. Bundle provenance includes the definitions required to interpret the evidence without access to the connected build system.

Bundle metadata records repository OpenPGP coverage as `none`, `partial`, or `all` from signatures that were actually verified. The compatibility `signature_verification` field reports `openpgp` only when every participating repository was verified. A configured keyring does not count as verification when the selected repository policy did not perform the signature check.

## Network and credential handling

<img width="1533" height="959" alt="47244727245782458" src="https://github.com/user-attachments/assets/62cf1129-07d2-435f-b877-11e8cbce059a" />

Repository acquisition is designed around source boundaries:

- credentials are scoped to their source origin;
- credential-bearing requests do not freely follow cross-origin redirects;
- HTTPS-to-HTTP redirect downgrade is rejected;
- signed URL/query credentials are treated as sensitive;
- custom repositories can declare additional sensitive query-field names, and can separately opt specific bearer fields into same-origin child-URL inheritance;
- effective origins after redirects are recorded for evidence decisions;
- repository-relative paths are confined to the selected repository;
- metadata and decompression operations use explicit resource limits.

Frozen Windows releases use a staged GnuPG `gpgv` verifier. Bundle signing separately requires `gpg` on PATH and an operator secret key. Production build tooling authenticates the staged verifier inputs, signs the staged PE files when configured, embeds their expected hashes in the executable, and prevents a frozen build from silently falling back to an arbitrary verifier on `PATH`.

## Workloads

Feathered includes 29 built-in workload definitions, including:

- Docker Engine;
- Podman, Buildah, and Skopeo combinations;
- nginx and Apache;
- PostgreSQL and MariaDB;
- Python and OpenJDK runtimes;
- Ansible;
- kernel headers and DKMS;
- Cockpit;
- Git;
- network diagnostics;
- security/audit tooling;
- storage administration;
- build toolchains;
- system-administration utilities;
- monitoring tools;
- PKI/TLS tooling;
- Kubernetes node and client packages;
- VKS node OS package additions;
- custom package sets.

Vendor-backed workloads such as Docker and Kubernetes keep their root packages tied to the appropriate vendor repository while normal enabled OS and supplemental repositories remain available for dependency analysis. **Workload packages only** is a deliberate root-artifact option, not an automatic consequence of using a vendor repository.

**VKS node OS package additions** is a contextual package workflow rather than a fixed package list. Selecting it keeps the ordinary target-OS package chooser and dependency resolver, then layers VKS-sensitive package classification, optional installed-inventory baseline pinning, advisories, and Image Baker draft output over the selected additions. Changing to another Content choice clears VKS-owned package roots and policy state. Changing to an incompatible target removes the VKS workflow and returns the wizard to the normal workload layout. Downstream choices such as dependency mode do not exit VKS context.

An optional `workloads.json` can replace or extend built-in workload definitions. Signed organization catalogs are supported through the companion workload-catalog signature/keyring convention described in the source.

For Kubernetes-specific behavior, see [KUBERNETES.md](KUBERNETES.md).

## Running from source on Windows

1. Extract the complete release archive into a normal directory. Do not run it from the ZIP preview.
2. Install Python 3 with Tk support.
3. Double-click `run_gui.bat` from the extracted `Feathered_1.3.0` directory.

When dependencies are missing, the launcher installs them from `requirements-runtime.lock` with hash verification and binary wheels only. `requirements.txt` remains the direct dependency specification. The complete `feathered_app` package must remain beside the launcher and top-level source files.

## Running on Ubuntu or Debian

Both the existing GUI and CLI are available through the Linux source installer.
Install `python3`, `python3-venv`, `python3-tk`, `ca-certificates` and `gnupg`, then
run these commands from the extracted source directory:

```bash
bash install_linux.sh
bash run_gui.sh
bash run_cli.sh --help
```

For headless machines, omit `python3-tk` and use `bash install_linux.sh --cli-only`.
Setup provides `feathered` (CLI) and `feathered-gui` commands plus an optional
application-menu entry. See [LINUX.md](LINUX.md) for offline installation,
updates, platform validation and directory choices.

## Target inventory

Target inventory is optional. Load it when you want repository planning to account for the packages and capabilities already installed on the disconnected system. To capture one, copy both inventory files to the target:

```text
target_inventory.sh
target_inventory_details.py
```

Keep them in the same directory and run:

```bash
bash target_inventory.sh target-inventory.txt
```

Copy the resulting inventory back to the connected Feathered workstation and select it for the build.

The collector uses native package-state sources where available, including `rpm`/DNF state, `dpkg-query`, and pacman configuration/database information. Python 3 is used for richer relationship capture.

## Command-line builds

Saved build specifications can be inspected and executed without Tk:

```bash
python feathered_cli.py show --spec build.json
python feathered_cli.py build --spec build.json --out ./bundles
```

Portable build specifications exclude local private-key paths. Saved repository URLs may contain credentials; displayed summaries redact those credentials while preserving the repository location. Runtime credentials and local trust material can be provided separately:

```bash
python feathered_cli.py build \
  --spec build.json \
  --runtime-config runtime.json
```

CLI decisions fail closed unless the corresponding acceptance option is supplied. See [CLI.md](CLI.md) for exit codes, output-reuse policies, runtime configuration, and the Python build API.

## Repository utilities

Feathered includes repository-maintenance workflows for existing package directories. These can regenerate native repository metadata while distinguishing retained Feathered provenance from locally introduced content.

Existing-output publication is transactional. Additive publication verifies inherited payloads against their recorded provenance before reusing prior evidence.

## Bundle sealing and receiver verification

A bundle can be sealed with a signed index. Sealed direct-install workflows verify the expected file set before target checks or package-manager execution.

For a stronger receiver bootstrap, distribute `trusted_receiver.py` and the operator public keyring through a trusted channel separate from the transferred bundle, then run:

```bash
python3 trusted_receiver.py /media/bundle /path/operator-keyring.gpg --install
```

A verifier stored only inside an untrusted bundle cannot independently establish trust in its own contents. With `--install`, the trusted receiver copies the complete bundle into protected temporary staging, removes write access, makes the staged tree root-owned, verifies that staged copy, and executes only from the protected tree.

## Application architecture

The desktop application is organized under `feathered_app/` with `app.py` as the Tk composition root. Build specifications, preparation, service contracts, repository/source scoping, and the headless execution path are separated from the GUI.

The internal split is complete for the current scope: GUI composition, portable
requests, build preparation and execution, package-family backends, and shared
transport/publication code have defined owners. Compatibility exports and GUI
mixins are retained interfaces. Further extraction is optional maintenance.

See [feathered_app/ARCHITECTURE.md](feathered_app/ARCHITECTURE.md) for those
boundaries and [FINALIZATION.md](FINALIZATION.md) for this review's changes and
validation limits. Completing the source split does not certify a Windows binary;
release builds still need the platform gates described in [VALIDATION.md](VALIDATION.md).

## Development checks

Common source checks are:

```bash
python -m mypy
python check_host_contracts.py
ruff check .
python -m compileall -q .
python write_source_manifest.py
python verify_source_checksums.py
```

`SOURCE-SHA256.json` is generated from the final tree and ignored by Git. Generate
it after merges or source edits, then verify the same tree. Do not resolve branch
merges by choosing one side's checksum manifest.

The release test runner executes the full pytest corpus in bounded batches and
reconciles each test with its setup/call/teardown outcomes:

```bash
python release_test_runner.py
```

On a Linux development host with Xvfb available, Tk portions can be exercised with:

```bash
FEATHERED_USE_XVFB=1 python release_test_runner.py
```

The generated `validation/release-gate/SUMMARY.md` records actual outcome counts,
source identity and environment. Full phase records and failure logs are retained
beside it. Platform skips are reported separately and require Linux coverage.
See [VALIDATION.md](VALIDATION.md) for the checks and reproduction instructions.

## Building the Windows release

`build_exe.bat` is the production Windows build entry point. Production dependencies are pinned with hashes in `requirements-build.lock` and installed as binary wheels only.

The release pipeline includes source checks, regression tests, PyInstaller packaging, staged verifier policy generation, release-manifest generation, checksum generation, and optional Authenticode signing. Review the build script and required environment variables before producing a public binary.

## Security reports

See [SECURITY.md](SECURITY.md).

## License

Feathered-authored source code is licensed under the MIT License. See [LICENSE](LICENSE).

Compiled distributions include third-party components under their own licenses. See [NOTICE.md](NOTICE.md).
