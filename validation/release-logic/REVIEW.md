# Release logic follow-up

Reviewed 2026-09-21 against the cumulative source update derived from
`6f409f2a84a927bd7bafbfeebaff8c1e7fecee93`. The source identity is recorded in
`source-SHA256.json`. This update supersedes r3 and includes all previous fixes.

## Fixed behavior

- Captured Conflicts and Breaks survive inventory loading. RPM inventory capture
  now includes conflict declarations. Selected packages are checked against the
  packages that remain installed, in both directions. Provider search can reject
  an incompatible provider and select a compatible alternative.
- RPM hard `user()` and `group()` requirements use normal dependency resolution.
  An available account-provider package is included; a missing provider remains
  unresolved. Package-only acquisition keeps its existing behavior.
- A failing module dependency group no longer prevents unrelated nonmodular
  requests from resolving. Its modular candidates and competing nonmodular
  replacements stay excluded. Affected roots and dependencies retain the module
  diagnostic. Selected module groups still need a compatible common platform.

No provenance defaults changed. No new inventory requirement, package-removal
permission, or user confirmation was introduced. To use installed RPM conflict
metadata, collect a fresh inventory with the updated companion script. Older
inventories remain accepted and cannot supply relationships they never captured.

## Results

- Full pytest corpus: **1758 passed, 2 failed, 0 skipped, 0 errors**
  out of 1760 tests. No tests were deselected.
- All 21 new regressions passed, including provider alternatives, retained and
  replaced packages, account dependencies, module scope, and platform consistency.
- Native APT simulation passed all four installed-conflict cases: selected or
  installed packages declaring Conflicts or Breaks. Each case independently checks
  Feathered's conflict result and APT's rejection of the same package/target pair.
- Native DNF 4.14.0 dependency resolution and downloads passed four ordinary
  scenarios, including account dependencies, and five module scenarios. One
  ordinary scenario also used loopback HTTP. RPM 4.18.2 built the fixtures.
- Ruff and Mypy passed; Mypy covered 81 configured source files.
- Host contracts accepted the valid fixture and rejected all 53 malformed cases.
- Python source compilation passed for 221 files.
- Generated RPM, signed RPM, APT, and Arch installers passed shell syntax checks.

## Remaining validation limits

The two pytest failures are the same GPG key-generation failures recorded in the
initial review. This sandbox prevents the Unix-domain socket needed by gpg-agent.
They remain failures in the report, not skipped tests or successful checks.

The complete native APT gate was attempted but its repository update could not
switch to the APT acquisition user: the sandbox denies setgroups/setuid. The new
conflict fixtures use native simulation of local emitted packages and an isolated
installed-status file. They require no repository acquisition and passed without
changing APT's sandbox settings.

RPM's chroot transaction test remains unavailable here, as recorded by the r3
native transaction attempt. The separate DNF diagnostic uses `--downloadonly`;
it proves dependency resolution and payload transfer, not RPM transaction testing
or actual installation. Production conformance retains `tsflags=test`.

Windows frozen builds, signing, media mounting, actual receiver installs, native
pacman conformance, and the full release matrix require their normal hosts. The
pytest corpus here used ordinary pytest and Xvfb, not the batched production
release runner. This is not release acceptance and does not certify all possible
repository and target states.

## Reproduction

The standard native jobs now include these fixtures automatically:

```bash
python native_conformance.py --require apt
python native_conformance.py --require dnf
python release_test_runner.py
```

For focused source regressions:

```bash
python -m pytest tests/test_release_logic.py tests/test_module_runtime.py
```

For local DNF dependency resolution and downloads only:

```bash
python validation/release-logic/native_dnf_solve_probe.py
```

## Evidence

- `pytest.xml`, `pytest.log`, `results.json`: full-corpus results.
- `static-checks.log`: static and generated-installer checks.
- `native-apt-conflicts.log`: four native conflict simulations.
- `native-dnf-solves.log`: ordinary and modular DNF dependency checks.
- `native-apt-gate-attempt.log`: blocked acquisition-user switch.
- `native_dnf_solve_probe.py`: the explicitly limited local diagnostic adapter.
- `source-SHA256.json`: cumulative source identity, excluding validation outputs.

The ZIP contains repository-relative replacement and new files. Extract into the
checkout and allow overwrites. No tracked file needs deletion. Its overlay onto
the originally supplied archive was verified against the complete source manifest.
