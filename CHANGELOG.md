# 1.3.0 - 2026-09-14

## Added

- Linux GUI and CLI source installation with per-user launchers, desktop integration, and offline wheel-directory support.
- SHA-512 and SHA-384 APT Release manifest support alongside SHA-256, including matching by-hash index URLs.

## Changed

- Arch Linux built-in repositories use the official Fastly mirror instead of the geo-routed hostname.
- Installed inventory is optional for Arch, Artix, and VKS workflows. When no inventory is loaded, dependency planning falls back to repository-derived closure instead of blocking the build.
- Receiver preflight only requires a target inventory for plans that explicitly declare an inventory-backed baseline.
- Independent-evidence tooltips are dismissed when their source widgets or wizard panes are hidden or destroyed.

## Fixed

- Corrected Ubuntu APT index verification when Release metadata publishes package indexes under SHA-512 rather than SHA-256.
- Allowed valid empty APT pockets to remain selected in repository mirror builds instead of treating zero package records as a failed source.
- Empty Ubuntu update and security pockets now explain that the indexes are valid and that no packages have been published to the selected pocket yet.
- Missing APT suites are reported from the repository's advertised `dists/` entries, including an explicit Docker CE message when the selected Ubuntu suite is not published.
- Corrected checksum inspection for empty APT repositories so the provenance view can call the APT explanation helper without a runtime NameError.
- Corrected stale TLS-certificate diagnostics that could count hosts from earlier repository checks.
- Corrected the independent-evidence "Testing..." tooltip so it cannot remain above unrelated wizard pages after navigation.
- Corrected bundle-characterization tests so runtime Python and zstandard versions do not make golden output platform-specific.
- VKS node OS package additions now use the shared exact-package chooser with clear empty-state guidance instead of presenting an unpopulated selection plan.
- Exact package roots and prior analysis are cleared when the Content choice changes, preventing packages selected in another mode from carrying into VKS analysis.
- Exact-package validation failures return to the package chooser on Repositories instead of an unrelated Content control.
- Package downloads now report bytes transferred while each artifact is streaming, including aggregate progress, transfer rate, and estimated time remaining.
- RPM receiver preflight preserves coinstalled versions with the same package name and architecture, including install-only kernel packages.
- Trusted receiver installation stages the complete bundle into a root-owned read-only tree before verification and execution.
- The standard-library zstd fallback enforces the metadata expansion limit while decompression is still in progress.
- Repository transport type annotations no longer contain an unresolved `Set` name.
- Repository maintenance rejects symbolic links inside the selected repository root instead of following package links outside it.
- Source integrity manifests are generated from the final merged tree instead of being tracked as merge-sensitive source files.
- Repository-relative URL validation canonicalizes nested percent encoding to a fixed point with a bounded fail-closed limit before containment checks.
- Windows and Linux source dependency installation uses a hash-locked binary-wheel runtime requirements file.

# 1.2.12 - 2026-09-11

## Added

- Tk-free preparation and execution path for saved build specifications.
- Public command-line build workflow with explicit runtime credential/trust inputs.
- Kubernetes release/EOL knowledge refresh with cached last-known-good data and bounded recovery behavior.
- Improved target-inventory and source-policy replay for deterministic headless builds.

## Changed

- Build workers consume frozen request state instead of reading live Tk variables.
- Exact saved package identities are resolved against current metadata without silently replacing the requested version.
- Mirror selection, source settings, signing choices, differential baseline state, and output naming are carried through the frozen build request.
- Trust findings, conflict decisions, package-only decisions, and existing-output publication policies use explicit service interfaces shared by GUI and headless execution.
- Repository/source participation is represented through typed scope and capability records.

## Fixed

- Corrected GUI state and rendering issues in differential, Kubernetes, and repository-selection workflows.
- Corrected release-state leakage between tests and several source-selection edge cases.
- Corrected CLI success handling so a successful exit requires an actual published output directory.
- Made randomized resolver-oracle reproduction deterministic across `PYTHONHASHSEED` values.
- Corrected cancellation and validation reporting in prepared/headless execution.

# 1.2.11

- Removed remaining build-worker dependence on live Tk state.
- Routed trust, conflict, and waiver decisions through injectable policies so builds can run without a GUI event consumer.
- Strengthened worker cancellation and completion handling.

# 1.2.10

- Unified the reported application version across GUI, provenance, and runtime identifiers.
- Corrected source-method and repository-pane state transitions.
- Added release/version consistency checks.

# 1.2.9

- Introduced immutable `BuildSpec` capture for target, content, sources, mirror settings, output policy, and provenance settings.
- Established the frozen-request boundary used by later headless execution work.

# 1.2.8

- Corrected a startup failure in the modularized UI.
- Added real application-construction coverage so composition/startup failures are detected directly.

# 1.2.7

- Stabilized footer/status rendering for large conflict and failure messages.
- Improved unified-mirror conflict presentation and operator decision handling.

# 1.2.6

- Isolated transaction-repository and mirror-repository state so acquisition modes cannot contaminate one another.
- Added explicit unified-mirror behavior and repository-universe separation.

# 1.2.5

- Corrected generated local repository URLs for paths containing spaces and other escaped characters.
- Hardened direct-install path handling for APT, DNF/YUM, and pacman outputs.

# 1.2.4

- Strengthened repository participation, target-state reconciliation, exact root requests, retained-package relationship handling, differential receiver prerequisites, and publication/cache contracts.
- Added conservative Arch full-upgrade planning and richer RPM module-metadata preservation.
- Added source-tree integrity manifest generation and verification.

# 1.2.3

- Added independent repository evidence relationships and conditional evidence policies.
- Added separate mirror publications and explicit unified-mirror conflict/equality rules.
- Strengthened transactional publication, signed-bundle invalidation rules, release-state discovery, APT release identity checks, and security-sensitive URL handling.
- Expanded native package-manager conformance coverage and assurance semantics.

# 1.2.2

- Added authenticated bundled-verifier policy for frozen Windows releases.
- Made required native-conformance tiers fail when unavailable instead of silently passing as skipped.
- Expanded release signing, source integrity, and verifier-integrity gates.

# 1.2.1

- Added armored OpenPGP keyring handling and bounded validation.
- Hardened the Windows production build and release manifest/checksum generation.
- Added optional Authenticode signing support.

# 1.2.0

- Split the former monolithic application implementation into responsibility-oriented modules under `feathered_app/` while retaining the public `App` surface.
- Added architecture documentation and compatibility routing for existing integrations/tests.
