# Release verification

Source completion and binary release acceptance are separate decisions. The
current architecture is described in `feathered_app/ARCHITECTURE.md`. The review
and local results for this update are in `FINALIZATION.md` and
`validation/finalization/`. The module follow-up is recorded in
`validation/module-runtime/`. The subsequent installed-conflict, RPM account,
and module-scope fixes are recorded in `validation/release-logic/`.

## Required checks

Run from the repository root with the runtime dependencies and the configured
analysis tools installed:

```bash
python check_python_sources.py
python -m mypy
python check_host_contracts.py
ruff check .
python check_installer_syntax.py
python write_source_manifest.py
python verify_source_checksums.py
python release_test_runner.py
```

On a headless Linux development host with Xvfb and xauth installed:

```bash
FEATHERED_USE_XVFB=1 python release_test_runner.py
```

The release runner collects the full test corpus and executes it in bounded
batches. It reconciles test IDs with setup, call, and teardown results. Missing,
stale, incomplete, skipped, or contradictory evidence fails according to the
platform policy. Normal pytest reporting and shutdown remain enabled. A zero
subprocess exit alone is insufficient.

## Current run output

The default report directory is `validation/release-gate/`:

- `SUMMARY.md`: outcome counts, source identity, interpreter, and environment.
- `summary.json`: individual outcomes and subprocess status.
- `collection.json` and `batch-NNN.json`: collection and phase records.
- `*.log`: normal diagnostics, including crashes and timeouts.

Use `--report-dir PATH` to choose a different directory and `--timeout SECONDS`
to change the default 300-second collection/batch deadline. A timeout fails the
gate and stops the child process tree.

`SOURCE-SHA256.json` is generated from the final tree and ignored by Git.
Generate it after edits or merges, then verify the same tree. Validation reports
are excluded from the source manifest so that writing evidence does not change
the identity of the code it describes.

## Platform coverage

The Linux full-corpus gate requires Tk/display support, native package fixture
tools, gpg, and gpgv. It accepts no skips. Windows accepts only the explicit
file/reason pairs in `release_test_runner.WINDOWS_SKIPS`; those cases require
coverage in the Linux gate. Missing display, unrelated skips, collection skips,
deselection, xfail, and xpass fail release acceptance.

The GitHub workflows cover Windows source and media mounting, Linux installation,
native package-manager conformance, and static analysis. Production publication
requires the configured jobs for the same Git SHA, authenticated dependency
installation, the staged verifier, and the production signing path. A local
source test run does not establish that these remote jobs passed.

## Native RPM module coverage

`python native_conformance.py --require dnf` includes ordinary RPM dependency
checks and the modular scenarios in `native_dnf_modules.py`. It requires DNF 4,
rpmbuild, createrepo_c, modifyrepo_c, and the Python runtime dependencies. The
existing Rocky Linux 9 CI job supplies these tools.

The modular cases build RPMs with real modularity labels, load modulemd through
repository metadata, build Feathered bundles, and ask DNF to test transactions
using only those bundles. Cases cover a dependent stream without its own default,
a context selected by captured stream state, a platform-dependent context, and
rejection of a disabled runtime dependency, and an ordinary package request
alongside unrelated ambiguous module contexts. The positive cases also cover RPM
version requirements that omit a release, such as `runtime = 1.0`.

The ordinary DNF cases include hard `user()` and `group()` requirements and the
package providing those accounts. `native_installed_conflicts.py` adds four APT
simulation cases for selected and installed Conflicts/Breaks. They load captured
relationships, verify that Feathered reports the conflict, and independently
check native rejection using the emitted package and an isolated status file.

CI retains `tsflags=test`. A local dependency solve or download-only check is
useful evidence but does not pass that transaction gate. DNF 5 without modularity
support cannot substitute for this DNF 4 coverage.

## Historical reports

Other directories under `validation/` contain results from earlier source trees
and intermediate failed runs. Their recorded source identity determines what
they establish. They are retained for history, not used as the current gate.
Old batch names and implementation instructions do not define outstanding work.
Use a newly generated report for the candidate being released.

## Dependency updates

Runtime installers consume `requirements-runtime.lock`; production builds consume
`requirements-build.lock`. Update the direct specification and complete lock
closure together. Verify the actual wheel hashes and platform tags. The release
build targets Windows x86-64 with CPython 3.13; Linux and Windows source installs
support the interpreter/platform combinations documented in the runtime lock.

`stage_gpgv.ps1` pins the official Windows GnuPG installer and SHA-256.
`install_windows_python.ps1` pins the release interpreter installer and SHA-256.
Update version, filename, hash, and associated tests together. Downloading and
hashing an installer validates the pin, but does not test executing it on Windows.
