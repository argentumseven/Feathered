# Finalization validation

Finalized 2026-09-21 against the supplied source for commit
`6f409f2a84a927bd7bafbfeebaff8c1e7fecee93`, with the accompanying changes applied.

## Results

- Full pytest corpus: **1706 passed, 2 failed, 0 skipped, 0 errors**
  out of 1708 collected tests. No tests were deselected.
- The 17 new advisory/signing tests passed, including four real GUI cases.
- Ruff passed. Mypy passed for 81 configured source files.
- Host contracts accepted the valid fixture and rejected 53 malformed capabilities.
- Python compilation passed for 215 in-scope source files.
- Generated RPM, vendor-signed RPM, APT, and Arch installers passed `bash -n`.
- All 14 locked Windows build wheels downloaded with hash verification.
- All 34 runtime/build wheel hashes matched PyPI release metadata; none was yanked.
  Runtime coverage includes CPython 3.10-3.14 on Windows amd64 and glibc Linux x86-64.
- The GnuPG and CPython Windows installers matched their published SHA-256 values.
- Devuan's repository warning was inspected in the running GUI.

This is not a passing release gate. The complete corpus was run with ordinary
pytest, not the batched production release runner. The two failures were:

- `test_openpgp_verification_round_trip`
- `test_ascii_armored_keyring_verifies_with_gpgv_only`

Both failed during test-key generation because gpg-agent could not start.
The sandbox rejects AF_UNIX socket creation with `Operation not permitted`.
The same failures occurred before application changes. They remain failures in
the report; they were not skipped or treated as successful signature checks.
Run them on a normal host as part of the required full release gate.

## Environment and limits

Linux, Python 3.12.14, pytest 9.1.1, Mypy 1.18.2, Ruff 0.14.2.
GUI tests used Xvfb with a TCP display inside the same process environment.
Its executable/compiler/cache paths were relocated into the writable workspace;
no application display code was changed for this setup. Temporary test files
were kept outside the source tree. Earlier display-setup diagnostics are not
counted as passing runs.

Windows installer execution, frozen binaries, Authenticode, media mounting, and
the complete native APT/DNF/pacman conformance matrix were not tested locally.
The existing CI requirements remain in force for the resulting Git commit.

## Evidence

- `pytest.xml`, `pytest.log`, and `results.json`: full-corpus outcomes.
- `static-checks.log`: configured static and generated-installer checks.
- `dependency-versions.json`: build-package versions observed on PyPI.
- `dependency-hashes.json`: exact lock hashes mapped to published wheel filenames.
- `windows-wheel-download.log`: authenticated cross-platform wheel download.
- `installer-hashes.json`: downloaded installer identities; neither was executed.
- `source-SHA256.json`: final source manifest, excluding validation output.

Reproduce application checks using the commands in `VALIDATION.md` with Tk/Xvfb,
gpg/gpgv, and native fixture tools available on a normal Linux host. Generate a
fresh release-runner report for the candidate commit.
