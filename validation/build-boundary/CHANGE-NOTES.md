# Build-boundary delivery

Base: b14bf5e0de840269289e5c2e728f1e17e26c39a7 (GitHub main reviewed 2026-09-13).
Implementation: aa3a685f4725f7b12c2d96be252a77c94097ad12.

The prior item-2-to-5 application work is present upstream. Subsequent changes
concentrate on native-conformance CI, Windows Python/Tk bootstrapping, production
interpreter selection, and a captured-draft regression fixture.

Chosen path: strengthen the prepared-plan/execution boundary before backend
extraction. See ../../BUILD-BOUNDARY.md for exact ownership and typing scope.
The constructor now owns its input graph; direct callers cannot change a run by
mutating the original objects. Mutable verification state is preserved inside
that graph. Feedback and mirror event mapping use concrete checked adapters.
The broad source/catalog/output host is not claimed fully typed.

Validation:
- Unmodified baseline: 1,341 passed, zero skips/deselections.
- Four ownership regressions failed before the constructor change.
- Focused ownership/headless/replay/GUI coverage: 104 passed.
- Additional actual GUI-versus-CLI artifact parity: one passed.
- Mypy: 48 checked roots; host contracts reject 47 malformed capabilities.
- Ruff and generated installer shell syntax pass.
- Final complete-corpus result: ../build-boundary-gate/SUMMARY.md and summary.json.

Parity compares payload hashes, package identities, source participation,
source-policy metadata, provenance assertions and installer bytes. Only the
provenance creation instant and generated bundle ID are normalized.

Upstream release blocker: https://github.com/argentumseven/Feathered/actions/runs/34737027821
passed APT, DNF, pacman and static analysis, but its Windows source/mount job
failed in the Python/Tk bootstrap. The public annotation only reports exit code
1. Detailed log access returned HTTP 403. No bootstrap fix, Windows execution,
frozen binary, signing, or remote CI pass is claimed for this delivery.

This ZIP is the complete source application based on the reviewed head, with a
reviewable patch and validation evidence. It has not been pushed or merged.

The parity fixture has the same exact missing-dpkg Windows exception as existing
Linux repository fixtures. Missing Tk is not permitted; Linux executes it fully.
