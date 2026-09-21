# Finalization review

Reviewed 2026-09-20 and finalized 2026-09-21 against the supplied source archive for commit
`6f409f2a84a927bd7bafbfeebaff8c1e7fecee93`. The public main-branch commit feed
matched that source revision at review time. No remote repository was changed.

## Decision

Stop the general decomposition work here. The current source has usable boundaries
between GUI composition, portable requests, build preparation, execution, package
backends, and shared infrastructure. Compatibility exports in `core.py`, App
mixins, and grouped views of GUI state are retained contracts. Their presence
does not mean the extraction is unfinished.

APT and Arch still keep substantial family-specific code in `apt_core.py` and
`arch_core.py`. Some background producers retain their existing ownership model.
These are deliberate limits of the current split, not claims that every file is
small or every operation shares one abstraction. Further restructuring should
solve a concrete maintenance or behavior problem.

This is a source finalization recommendation. Public binary release acceptance
still requires the Windows and native-platform jobs for the resulting commit.
No review can establish that every possible repository or native transaction is
correct. APT, DNF/YUM, and pacman retain final authority on their targets.

## Changes

- Keep the normal workload, exact-package, and mirror workflows. Preserve optional
  target inventory, package-only acquisition, optional provenance, and the existing
  default verification policy. No new build confirmation or keyring requirement.
- Show HTTP advice on Repositories and Provenance and Keying. Devuan's HTTP URLs
  remain unchanged. The warning follows the actual build scope, including mirror
  selections, and recommends a trusted archive keyring. It explains that signature
  verification authenticates content but does not encrypt the connection.
- Label keyrings as configured or bypassed. Selecting a key file no longer makes
  the repository editor claim that a signature has been verified.
- Distinguish gpgv verification from gpg signing. A bundled verifier enables
  signature checks; bundle signing requires a separate signer and operator key.
- Update the GnuPG, PyInstaller, and Windows CPython pins with matching hashes.
- Replace stale validation-batch commentary and missing document references with
  current architecture, reproduction, and release acceptance documentation.

## Dependencies

| Component | Previous | Updated or retained | Verification |
| --- | --- | --- | --- |
| Staged Windows GnuPG | 2.5.21 | 2.5.22 | Downloaded installer matches published SHA-256 |
| Windows build CPython | 3.13.14 | 3.13.15 | Downloaded installer matches published SHA-256 |
| PyInstaller | 6.22.2 | 6.22.3 | Windows wheel hash and locked dependency download |
| Runtime zstandard | 0.25.0 | 0.25.0 | PyPI release metadata and runtime lock |
| Runtime PyYAML | 6.0.3 | 6.0.3 | PyPI release metadata and runtime lock |
| Other build packages | Existing pins | Retained | Current PyPI versions and locked Windows wheel download |

The update stays on the existing CPython 3.13 build series. Static-analysis tools
remain the configured Mypy 1.18.2 and Ruff 0.14.2; those are development checks,
not bundled application dependencies. Linux GnuPG comes from the host's package
manager and is not replaced by the Windows staging pin.

Primary sources checked for this update:

- [GnuPG downloads](https://www.gnupg.org/download/index.html)
- [GnuPG installer checksums](https://www.gnupg.org/download/integrity_check.html)
- [CPython 3.13.15 release and installer checksum](https://www.python.org/downloads/release/python-31315/)
- [PyInstaller 6.22.3](https://pypi.org/project/pyinstaller/6.22.3/)
- [zstandard](https://pypi.org/project/zstandard/)
- [PyYAML](https://pypi.org/project/PyYAML/)
- [Devuan package sources](https://www.devuan.org/os/packages)

## Validation

The initial local results are recorded in `validation/finalization/REVIEW.md`.
The module changes and their results are in `validation/module-runtime/REVIEW.md`.
The latest follow-up is `validation/release-logic/REVIEW.md`.
The update does not turn failed or unavailable checks into passes. Earlier
reports elsewhere in `validation/` describe earlier source trees.

The local environment cannot execute Windows installers, a frozen Windows build,
Authenticode signing, or the full native APT/DNF/pacman conformance matrix.
Download/hash checks establish the installer pins, not runtime behavior on Windows.

## Release follow-up correction

The first finalization zip updated the Python installer pin but missed two
hard-coded `(3,13,14)` checks in the bootstrap and builder. The bootstrap would
reject Python 3.13.15. Both checks now match the installer, and a regression test
compares them with the declared version and lock-file contract. Use the revised
zip; it contains the complete update and supersedes the first one.

## RPM module follow-up

The module investigation found that the builder filtered out a required stream
unless it was separately enabled or default. Receiver-side DNF validation could
reject that incomplete bundle, but could not repair its missing payloads.

The builder now resolves unambiguous module runtime requirements before RPM
selection. Captured enabled and disabled streams are respected. Captured
`PLATFORM_ID` constrains platform-dependent contexts and is checked by receiver
preflight. With no captured platform, module metadata can establish a unique
platform choice; that is repository-derived planning, not target verification.
Conflicting defaults, incompatible requirements, unresolved context choices, and
a bounded search limit produce explicit diagnostics. DNF's relaxed fallback
policies and automatic changes to enabled streams remain outside this planner.

Module metadata from participating RPM repositories remains in the bundle even
when those repositories contribute no selected payload. Nonmodular filtering
also checks virtual provides and the active module's demodularized package names.
Package-only acquisition bypasses module solving and retains its existing
limited assurance.

The native fixtures also exposed an RPM comparison bug: a requirement without a
release, such as `runtime = 1.0`, must accept package version `1.0-1`. Dependency
comparison now follows RPM's omitted-release rules, including version-only
provides against release-qualified inequalities. Explicit release comparisons
and package version ordering are unchanged.

Four real modular DNF scenarios now run in the existing native CI gate. Local
DNF 4 dependency resolution and package downloads passed all four. The sandbox
denied RPM's chroot transaction test, so full native transaction acceptance
still requires the normal CI host. See the follow-up report for exact results.

## Installed conflicts, RPM accounts, and module scope

The next review reproduced three gaps. APT plans could miss conflicts with
installed packages, RPM planning ignored hard account dependencies, and the r3
module change could reject an unrelated nonmodular request. These are now covered
by targeted regressions and native fixture checks.

Target capture and loading retain conflict declarations for Debian, RPM, and
Arch records. Planning checks selected packages against the retained installed
set in both directions. Debian Breaks is included. APT and RPM provider search
can select a compatible alternative instead of retaining a conflicting provider.
These checks do not authorize package removal or require a target inventory.
Old RPM captures lack conflict declarations; collect a fresh inventory using the
updated companion script to include them. Legacy captures remain accepted with
only the information they actually contain.

RPM `user()` and `group()` requirements now participate in normal provider
resolution. Missing providers remain unresolved; providers already captured as
installed can satisfy them. Package-only acquisition still skips dependency
planning.

Module runtime failures are isolated by dependency group. A failed group's RPMs
and competing nonmodular replacements remain excluded, but unrelated packages
can still be resolved. Requests for excluded roots or dependencies receive the
module reason. Selected modular groups are checked together for platform
compatibility before the result is finalized.

The native gate adds account-provider coverage, an unrelated-module scenario,
and four installed Conflicts/Breaks simulations. Local native results and the
remaining sandbox restrictions are recorded in the latest report. This update
supersedes r3; r3 is not the recommended release candidate.

## Applying the update

The delivered zip contains repository-relative replacement and new files. Extract
its contents into the existing Git checkout and allow overwrites. No tracked file
needs to be deleted. Review the diff and push the commit normally. The release
workflows will run against that commit. Keep the final source manifest generated
by the build rather than committing an older copy.
