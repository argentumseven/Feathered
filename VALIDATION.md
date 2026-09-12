# Release verification - 1.2.12

The 1.2.12 source tree includes automated checks for package/repository behavior, application startup and workflow logic, provenance and evidence semantics, hostile transport cases, source integrity, static typing, and native package-manager conformance harnesses.

## Recorded release checks

| Check | Recorded result |
| --- | --- |
| Full release test corpus | 1,205 tests collected; all release-runner batches passed |
| Focused Kubernetes/release-state run | 144 passed |
| Mypy | 45 configured roots passed |
| Host-contract gate | 39 malformed capability shapes rejected |
| Ruff | Passed |
| Python compilation | Passed |
| Source manifest check | Passed |

Current run logs are retained under `validation/` for the release snapshot. Historical repair-session logs are not part of the public source tree.

## Reproduction

```bash
python -m mypy
python check_host_contracts.py
ruff check .
python -m compileall -q .
python verify_source_checksums.py
python release_test_runner.py
```

On Linux development systems that need a virtual X server for Tk coverage:

```bash
FEATHERED_USE_XVFB=1 python release_test_runner.py
```

Native conformance can also be invoked through the repository's dedicated workflow/script where the required native package managers are available.

## Scope

These checks establish properties of this source/release snapshot and its deterministic fixtures. They do not turn Feathered into the authoritative target transaction solver; APT, DNF/YUM, and pacman retain that role when consuming the generated repositories.
