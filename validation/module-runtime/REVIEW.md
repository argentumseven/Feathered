# RPM module follow-up

Reviewed 2026-09-21. This cumulative update includes the earlier finalization
changes and the module fixes described in `FINALIZATION.md`.

## Results

- Full pytest corpus: **1737 passed, 2 failed, 0 skipped, 0 errors**
  out of 1739 tests. No tests were deselected.
- All 30 new module and RPM dependency regressions passed.
- Native DNF 4.14.0 resolved and downloaded all three positive modular fixtures.
  It rejected the disabled-dependency fixture. RPM 4.18.2 built the labeled RPMs.
- Native RPM dependency comparisons independently confirmed the ten omitted-release
  comparison cases used by the Python regression tests.
- Ruff passed. Mypy passed for 81 configured source files.
- Host contracts accepted the valid fixture and rejected 53 malformed capabilities.
- Python compilation passed for 218 source files.
- Generated RPM, signed RPM, APT, and Arch installer scripts passed `bash -n`.

The two pytest failures remain the GPG key-generation failures seen in the
original review. This sandbox denies the Unix-domain socket needed by gpg-agent.
They remain failures, not skipped tests or successful verification results.

## Native test limits

The full DNF transaction test was attempted. DNF resolved the first ordinary RPM
fixture, then RPM could not enter the test installroot: `Unable to change root
directory: Operation not permitted`. That is a failed local transaction gate.

The separate local probe used DNF's `--downloadonly` option to evaluate the four
modular fixtures without requesting a chroot transaction. Its log is explicitly
labeled as dependency resolution and downloads only. This established that DNF
can consume the emitted RPMs and modulemd for those cases. It did not establish
that RPM's transaction test or package installation completed.

The production conformance harness retains `tsflags=test`. The existing Rocky
Linux 9 CI gate now calls the modular harness after its ordinary dependency
cases. No skip, downgrade, or sandbox-specific option was added to production
code. Native tools used locally were extracted into a temporary workspace;
wrappers selected their libraries and relocated RPM configuration and logs.
They did not install packages into the host operating system.

Windows frozen binaries, signing, media mounting, actual receiver installs, and
the complete APT/DNF/pacman release matrix still require their normal CI or target
hosts. The full pytest corpus here was run with ordinary pytest and Xvfb, not the
batched production release runner. This report is not release acceptance.

## Scope

The builder follows module runtime dependencies and uses captured streams and
platform state to select an unambiguous context. It reports conflicting defaults,
incompatible requirements, ambiguity, or search exhaustion. It does not duplicate
DNF's relaxed fallback policies or change enabled target streams. Inventory is
optional, and package-only acquisition bypasses module solving.

Module metadata from participating RPM repositories is retained even when no RPM
from one of those sources is selected. Empty repositories with no package records
are not new module metadata sources for the package-list resolver. Receiver-side
DNF remains responsible for evaluating its actual target state and transaction.

## Evidence and reproduction

- `pytest.xml`, `pytest.log`, `results.json`: full-corpus outcomes.
- `static-checks.log`: static analysis and installer syntax checks.
- `native-module-solve.log`: native DNF dependency solves and downloads.
- `native-transaction-attempt.log`: sandbox rejection of RPM transaction testing.
- `native_solve_probe.py`: diagnostic adapter used for the local download-only
  check; it does not alter the production conformance gate.
- `source-SHA256.json`: the cumulative source identity, excluding validation logs.

On a normal Linux host with the tools listed in `VALIDATION.md`, run:

```bash
python native_conformance.py --require dnf
python release_test_runner.py
```

For the narrower diagnostic alone, run:

```bash
python validation/module-runtime/native_solve_probe.py
```

This update supersedes the earlier ZIPs. Extract it into the existing checkout
and allow overwrites. No tracked file needs deletion. The ZIP was also checked as
an overlay onto the originally supplied archive.
